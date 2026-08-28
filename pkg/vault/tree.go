package vault

import (
	"errors"
	"fmt"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/cloudfoundry-community/goutils/tree"
	"github.com/cloudfoundry-community/vaultkv"
	"github.com/jhunt/go-ansi"
)

// This is a synchronized queue that specifically works with our tree algorithm,
// in which the workers that pull work off the queue are also responsible for
// populating the queue. This is because of the recursive nature of the tree
// population. All workers are released when all workers are simultaneously
// waiting on an empty queue.
type workQueue struct {
	head   *workQueueNode
	tail   *workQueueNode
	c      *sync.Cond
	awake  int
	closed bool
}

type workQueueNode struct {
	next    *workQueueNode
	payload *workOrder
}

func newWorkQueue(numWorkers int) *workQueue {
	return &workQueue{
		c:     sync.NewCond(&sync.Mutex{}),
		awake: numWorkers,
	}
}

func (w *workQueue) Pop() (ret *workOrder, done bool) {
	w.c.L.Lock()
	//While it'd be more "correct" logically to put this inside the loop, its a
	// minor optimization to keep it outside - it all looks the same transactionally
	// anyway
	w.awake--
	for w.head == nil && !w.closed {
		//This would mean that all the workers would be waiting for something new
		// to enter the queue. Given that the workers are also responsible for
		// populating the queue, this means that nothing else can possibly enter
		// and that we're done
		if w.awake == 0 {
			w.closed = true
			w.c.Broadcast()
			break
		}

		w.c.Wait()
	}
	if w.closed {
		w.c.L.Unlock()
		return nil, true
	}

	w.awake++

	ret = w.head.payload
	w.head = w.head.next
	if w.head == nil {
		w.tail = nil
	}

	w.c.L.Unlock()
	return ret, false
}

func (w *workQueue) Push(o *workOrder) {
	w.c.L.Lock()
	if w.closed {
		w.c.L.Unlock()
		return
	}

	toAdd := &workQueueNode{payload: o}

	if w.tail != nil {
		w.tail.next = toAdd
	} else { //tail is nil iff head is nil
		w.head = toAdd
	}

	w.tail = toAdd

	w.c.L.Unlock()
	w.c.Signal()
}

func (w *workQueue) Close() {
	w.c.L.Lock()
	if !w.closed {
		w.closed = true
		w.c.Broadcast()
	}
	w.c.L.Unlock()
}

type workOrder struct {
	insertInto *secretTree
	operation  uint16
}

type secretTree struct {
	Name         string
	Branches     []secretTree
	Type         uint
	MountVersion uint
	Value        string
	Version      uint
	Deleted      bool
	Destroyed    bool
	// fetched marks a version node whose data the walk has already read (by
	// workGetLatest, in one request); getWorkType assigns it no further work.
	fetched bool
}

func (v *Vault) ConstructSecrets(path string, opts TreeOpts) (s Secrets, err error) {
	constructTreeOpts := opts
	//It's easier to analyze which secrets to purge once we have it structured as an array.
	//So we let the tree just naively fetch secrets, and then we can clean up the results later
	constructTreeOpts.SkipVersionInfo = opts.AllowDeletedSecrets && opts.SkipVersionInfo
	t, err := v.constructTree(path, constructTreeOpts)
	if err != nil {
		return nil, err
	}

	s = t.convertToSecrets()
	if !opts.AllowDeletedSecrets {
		if opts.FetchAllVersions {
			//A walk that asked for the whole history keeps a secret for the
			// sake of the versions it can still read. Dropping it because the
			// newest one happens to be deleted throws away the older ones with
			// it, which is data loss in an export.
			s.purgeWhereNoVersionAlive()
		} else {
			s.purgeWhereLatestVersionDeleted()
		}
	}
	//If we populated versions earlier and it wasn't asked for directly, lets clean them up now
	if opts.SkipVersionInfo {
		s.purgeVersions()
	}

	s.Sort()
	return s, nil
}

// This does not keep the list in a sorted order. Sort afterward
func (s *Secrets) purgeWhereLatestVersionDeleted() {
	for i := 0; i < len(*s); i++ {
		if len((*s)[i].Versions) == 0 || (*s)[i].Versions[len((*s)[i].Versions)-1].State != SecretStateAlive {
			(*s)[i], (*s)[len(*s)-1] = (*s)[len(*s)-1], (*s)[i]
			*s = (*s)[:len(*s)-1]
			i--
		}
	}
}

// purgeWhereNoVersionAlive drops only the secrets with nothing left to read.
// A secret keeping even one alive version is worth carrying: the caller asked
// for every version, and the ones it cannot read are recorded as placeholders
// rather than dropped, exactly as a deleted version in the middle of a history
// already was.
func (s *Secrets) purgeWhereNoVersionAlive() {
	for i := 0; i < len(*s); i++ {
		if !(*s)[i].hasAliveVersion() {
			(*s)[i], (*s)[len(*s)-1] = (*s)[len(*s)-1], (*s)[i]
			*s = (*s)[:len(*s)-1]
			i--
		}
	}
}

func (e SecretEntry) hasAliveVersion() bool {
	for _, version := range e.Versions {
		if version.State == SecretStateAlive {
			return true
		}
	}
	return false
}

func (s *Secrets) purgeVersions() {
	for i := range *s {
		(*s)[i].Versions = nil
	}
}

func PathLessThan(left, right string) bool {
	leftSplit := strings.Split(Canonicalize(left), "/")
	rightSplit := strings.Split(Canonicalize(right), "/")

	minLen := len(leftSplit)
	if len(rightSplit) < minLen {
		minLen = len(rightSplit)
	}

	for i := 0; i < minLen; i++ {
		if leftSplit[i] < rightSplit[i] {
			return true
		} else if leftSplit[i] > rightSplit[i] {
			return false
		}
	}

	if len(leftSplit) != len(rightSplit) {
		return len(leftSplit) < len(rightSplit)
	}

	//The canonical paths agree on every segment: the two are either the same
	// path spelled differently -- `/secret/a` against `secret//a` -- or one
	// names a folder and the other the secret at that folder's own path --
	// `secret/a/` against `secret/a`. A folder sorts after the secret at its
	// own path, since the folder's contents nest under that same prefix.
	leftIsDir := strings.HasSuffix(left, "/")
	rightIsDir := strings.HasSuffix(right, "/")
	if leftIsDir != rightIsDir {
		return !leftIsDir
	}

	//Neither the canonical path nor the folder/secret distinction tells the
	// two apart, which happens for two raw spellings of the very same path
	// (including left == right, where this reports false, satisfying no
	// path being less than itself). Breaking the tie on the raw string
	// itself, rather than looking at left alone, keeps the result the same
	// regardless of which side of the call left and right land on --
	// required for a strict weak ordering, and violated before this by
	// depending only on left's own trailing slash.
	return left < right
}

func (s Secrets) Sort() {
	sort.Slice(s, func(i, j int) bool { return PathLessThan(s[i].Path, s[j].Path) })
}

func (s1 Secrets) Merge(s2 Secrets) Secrets {
	ret := append(Secrets{}, s1...)
	for _, s := range s2 {
		idx := sort.Search(len(ret), func(i int) bool {
			return (s.Path == ret[i].Path || PathLessThan(s.Path, ret[i].Path))
		})
		if idx == len(ret) {
			ret = append(ret, s)
			continue
		}

		if s.Path == ret[idx].Path {
			continue
		}

		before := ret[:idx]
		after := append(Secrets{s}, ret[idx:]...)
		ret = append(before, after...)
	}

	return ret
}

func (t secretTree) convertToSecrets() Secrets {
	var ret Secrets
	t.DepthFirstMap(func(t *secretTree) {
		if t.Type == treeTypeSecret || t.Type == treeTypeDirAndSecret {
			thisEntry := SecretEntry{
				Path: Canonicalize(t.Name),
			}

			for _, version := range t.Branches {
				if version.Type != treeTypeVersion {
					continue
				}

				thisVersion := SecretVersion{
					Data:   NewSecret(),
					Number: version.Version,
					State:  SecretStateAlive,
				}

				if version.Destroyed {
					thisVersion.State = SecretStateDestroyed
				} else if version.Deleted {
					thisVersion.State = SecretStateDeleted
				}

				for _, key := range version.Branches {
					_ = thisVersion.Data.Set(key.Basename(), key.Value, false)
				}

				thisEntry.Versions = append(thisEntry.Versions, thisVersion)
			}

			ret = append(ret, thisEntry)
		}
	})

	return ret
}

const (
	treeTypeRoot uint = iota
	treeTypeDir
	treeTypeSecret
	treeTypeDirAndSecret
	treeTypeKey
	treeTypeVersion
)

const (
	opTypeNone uint16 = 0
	opTypeList        = 1 << (iota - 1)
	opTypeGet
	opTypeMounts
	opTypeVersions
	opTypeGetLatest
)

type Secrets []SecretEntry

func (s *Secrets) Append(e SecretEntry) {
	*s = append(*s, e)
}

type SecretEntry struct {
	Path     string
	Versions []SecretVersion
}

const (
	SecretStateAlive uint = iota
	SecretStateDeleted
	SecretStateDestroyed
)

type SecretVersion struct {
	Data   *Secret
	Number uint
	State  uint
}

type TreeOpts struct {
	//For tree/paths --keys
	FetchKeys bool
	//v2 backends show deleted secrets in the list by default
	//Leaving this unset will cause entries with the latest
	//version deleted to be purged
	//Ignored by constructTree. Just used by ConstructSecrets
	AllowDeletedSecrets bool
	//Overridden by FetchKeys
	SkipVersionInfo bool
	//Whether to get all versions of keys in the tree
	FetchAllVersions bool
	//GetDeletedVersions tells the workers to temporarily undelete deleted
	// keys to fetch their value, then delete them again
	GetDeletedVersions bool
	//Only perform gets. If the target is not a secret, then an error is returned
	GetOnly bool
	//SkippedForbidden, when non-nil, is incremented once for each node the
	// walk skipped because Vault denied access to it. The pointer is shared
	// across the concurrent tree workers.
	SkippedForbidden *atomic.Uint64
}

// noteSkippedForbidden records one access-denied skip if a counter is wired in.
func (o TreeOpts) noteSkippedForbidden() {
	if o.SkippedForbidden != nil {
		o.SkippedForbidden.Add(1)
	}
}

func (v *Vault) constructTree(path string, opts TreeOpts) (*secretTree, error) {
	numWorkers := runtime.NumCPU()
	if numWorkers < 1 {
		numWorkers = 1
	}

	queue := newWorkQueue(numWorkers)
	errChan := make(chan error)

	path = Canonicalize(path)
	if path == "" {
		path = "/"
	}
	ret := &secretTree{Name: path}
	err := ret.populateNodeType(v)
	if err != nil {
		return nil, err
	}
	if opts.GetOnly && ret.Type != treeTypeSecret && ret.Type != treeTypeDirAndSecret {
		return nil, fmt.Errorf("`%s' is not a secret", path)
	}
	operation := ret.getWorkType(opts)
	queue.Push(&workOrder{
		insertInto: ret,
		operation:  operation,
	})

	for i := 0; i < numWorkers; i++ {
		worker := treeWorker{
			vault:  v,
			orders: queue,
			errors: errChan,
			opts:   opts,
		}
		go worker.work()
	}

	//Workers return on errChan when they finish. They'll throw back nil if no
	// errors were encountered
	for i := 0; i < numWorkers; i++ {
		thisErr := <-errChan
		if thisErr != nil {
			err = thisErr
		}
	}
	if err != nil {
		return nil, err
	}

	//Make the output deterministic
	ret.sort()

	return ret, err
}

// Only use this for the base for the initial node of the tree. You can infer
// type much faster than this if you know the operation that retrieved it in the
// first place.
func (t *secretTree) populateNodeType(v *Vault) error {
	if t.Name == "/" {
		t.Type = treeTypeRoot
		return nil
	}

	var err error
	t.MountVersion, err = v.MountVersion(t.Name)
	if err != nil {
		return err
	}

	_, _, version := ParsePath(t.Name)
	if version > 0 {
		_, err = v.Read(t.Name)
		if err != nil {
			return err
		}
	}

	err = v.verifyMetadataExists(t.Name)
	if err != nil {
		if vaultkv.IsForbidden(err) {
			tokenerr := v.Client().Client.TokenIsValid()
			if tokenerr != nil {
				return err
			}
		} else if !IsNotFound(err) {
			return err
		}

		_, err := v.List(t.Name)
		if err != nil {
			return err
		}
		t.Type = treeTypeDir
	} else {
		t.Type = treeTypeSecret

		_, err := v.List(t.Name)
		if err == nil {
			t.Type = treeTypeDirAndSecret
		}
		if err != nil && !IsNotFound(err) {
			return err
		}

	}
	return nil
}

func (t *secretTree) getWorkType(opts TreeOpts) uint16 {
	ret := opTypeNone

	switch t.Type {
	case treeTypeRoot:
		ret = opTypeMounts
	case treeTypeDir:
		t.Name = strings.TrimRight(t.Name, "/") + "/"
		ret = opTypeList
	case treeTypeDirAndSecret:
		ret = opTypeList
		if latestOnlyKeyed(opts) && t.MountVersion == 2 {
			ret |= opTypeGetLatest
		} else if opts.FetchKeys || !opts.SkipVersionInfo {
			ret |= opTypeVersions
		}
	case treeTypeSecret:
		if latestOnlyKeyed(opts) && t.MountVersion == 2 {
			ret = opTypeGetLatest
		} else if opts.FetchKeys || !opts.SkipVersionInfo {
			ret |= opTypeVersions
		}
	case treeTypeVersion:
		if t.fetched {
			break // data already fetched by workGetLatest
		}
		if opts.FetchKeys && (opts.GetDeletedVersions || !t.Deleted && !t.Destroyed) {
			ret = opTypeGet
		}
	}

	if opts.GetOnly {
		ret &^= opTypeList
	}

	return ret
}

// latestOnlyKeyed reports whether a walk wants exactly the newest live
// version of each secret with its keys, the case a single data GET can
// answer without a metadata lookup.
func latestOnlyKeyed(opts TreeOpts) bool {
	return opts.FetchKeys && !opts.FetchAllVersions && !opts.GetDeletedVersions
}

func (s Secrets) Paths() []string {
	ret := make([]string, 0)

	//SecretEntry.Path is a literal Vault path. Callers parse what comes back
	// out of here, so emit safe's path:key syntax in both branches.
	for i := range s {
		if len(s[i].Versions) > 0 {
			for _, key := range s[i].Versions[len(s[i].Versions)-1].Data.Keys() {
				ret = append(ret, EncodePath(s[i].Path, key, 0))
			}
		} else {
			ret = append(ret, EncodePath(s[i].Path, "", 0))
		}
	}

	return ret
}

type TreeCopyOpts struct {
	//Clear will wipe the secret in place
	Clear bool
	//Pad will insert dummy versions that have been truncated by Vault
	Pad bool
}

func (s SecretEntry) Copy(v *Vault, dst string, opts TreeCopyOpts) error {
	if opts.Clear {
		err := v.Client().DestroyAll(dst)
		if err != nil {
			return fmt.Errorf("could not wipe existing secret at path `%s': %w", dst, err)
		}
	}

	var toDelete, toDestroy []uint

	if opts.Pad && len(s.Versions) > 0 {
		for i := uint(1); i < s.Versions[0].Number; i++ {
			setMeta, err := v.Client().Set(dst, map[string]string{"TO_DESTROY": "TO_DESTROY"}, nil)
			if err != nil {
				return fmt.Errorf("could not write secret to path `%s': %w", dst, err)
			}

			toDestroy = append(toDestroy, setMeta.Version)
		}
	}

	for _, version := range s.Versions {
		var toWrite map[string]string
		if version.State == SecretStateDestroyed {
			toWrite = map[string]string{"TO_DESTROY": "TO_DESTROY"}
		} else {
			toWrite = version.Data.data
		}

		setMeta, err := v.Client().Set(dst, toWrite, nil)
		if err != nil {
			return fmt.Errorf("could not write secret to path `%s': %w", dst, err)
		}

		switch version.State {
		case SecretStateDestroyed:
			toDestroy = append(toDestroy, setMeta.Version)
		case SecretStateDeleted:
			toDelete = append(toDelete, setMeta.Version)
		}
	}

	if len(toDestroy) > 0 {
		err := v.Client().Destroy(dst, toDestroy)
		if err != nil {
			return fmt.Errorf("could not destroy versions %+v at path `%s': %w", toDestroy, dst, err)
		}
	}
	if len(toDelete) > 0 {
		err := v.DeleteVersions(dst, toDelete)
		if err != nil {
			return fmt.Errorf("could not delete versions %+v at path `%s': %w", toDelete, dst, err)
		}
	}

	return nil
}

func (t secretTree) Basename() string {
	var ret string
	switch t.Type {
	case treeTypeRoot:
		ret = "/"
	case treeTypeDir:
		splits := strings.Split(strings.TrimRight(t.Name, "/"), "/")
		ret = splits[len(splits)-1] + "/"
	case treeTypeSecret, treeTypeDirAndSecret:
		splits := strings.Split(strings.TrimRight(t.Name, "/"), "/")
		ret = splits[len(splits)-1]
	case treeTypeKey:
		//The node name is path:key with the key segment escaped (workGet);
		// ParsePath splits on the last unescaped colon and unescapes.
		_, key, _ := ParsePath(t.Name)
		ret = key
	}

	return ret
}

func (t *secretTree) DepthFirstMap(fn func(*secretTree)) {
	fn(t)
	for i := range t.Branches {
		(&t.Branches[i]).DepthFirstMap(fn)
	}
}

func (s SecretEntry) Basename() string {
	parts := strings.Split(s.Path, "/")
	return parts[len(parts)-1]
}

func (t *secretTree) sort() {
	for i := range t.Branches {
		t.Branches[i].sort()
	}
	sort.Slice(t.Branches, func(i, j int) bool {
		if t.Branches[i].Name == t.Branches[j].Name {
			return t.Branches[i].Version < t.Branches[j].Version
		}
		return t.Branches[i].Name < t.Branches[j].Name
	})
}

func (s Secrets) Draw(root string, color, secrets bool) string {
	if len(s) == 0 {
		return ""
	}

	root = strings.Trim(Canonicalize(root), "/")
	var index int
	if len(root) > 0 {
		index = len(strings.Split(root, "/"))
	}

	printTree := s.printableTree(color, secrets, index)

	root = strings.Trim(root, "/")
	if root != strings.Trim(s[0].Path, "/") {
		root = strings.TrimSuffix(root, "/") + "/"
	}
	//Escape the printed root for the same reason as the segments below: a
	// literal ':' or '^' in it would otherwise read as key or version syntax.
	root = EscapePathSegment(root)
	if color {
		root = ansi.Sprintf("@C{%s}", root)
	}
	printTree.Name = root
	return printTree.Draw()
}

func (s Secrets) printableTree(color, secrets bool, index int) *tree.Node {
	if len(s) == 0 {
		return nil
	}

	//The leading slash is to simulate a root node
	firstSplit := strings.Split("/"+s[0].Path, "/")
	thisName := firstSplit[index]
	if index == 0 {
		thisName = "/"
	}
	isSecret := index == len(firstSplit)-1

	var dirFmt, secFmt = "%s/", "%s"
	if color {
		dirFmt, secFmt = "@B{%s/}", "@G{%s}"
	}

	//Escape the segment so a literal ':' or '^' in a path name is not read
	// back as key or version syntax.
	thisName = EscapePathSegment(thisName)
	if isSecret {
		thisName = ansi.Sprintf(secFmt, thisName)
	} else {
		thisName = ansi.Sprintf(dirFmt, thisName)
	}

	ret := &tree.Node{
		Name: thisName,
	}

	if isSecret {
		if len(s[0].Versions) > 0 && len(s[0].Versions[len(s[0].Versions)-1].Data.Keys()) > 0 {
			keys := s[0].Versions[len(s[0].Versions)-1].Data.Keys()
			sort.Strings(keys) // Sort keys for consistent output

			// Create child nodes for each key instead of appending to the name
			for _, key := range keys {
				keyName := fmt.Sprintf(":%s", EscapePathSegment(key))
				if color {
					keyName = ansi.Sprintf("@Y{%s}", keyName)
				}
				keyNode := &tree.Node{
					Name: keyName,
				}
				ret.Append(*keyNode)
			}
		}
	}

	//Now we need to simulate walking the "tree" by treating groups of the same
	// directory as "nodes in a tree" and thus grouping them into the next recursive call
	startIndex := 0
	if isSecret {
		startIndex = 1
	}
	for startIndex < len(s) {
		thisSplit := strings.Split("/"+s[startIndex].Path, "/")
		groupWord := thisSplit[index+1]
		//Make a separate entry for the secret
		if len(thisSplit) == index+2 {
			if secrets {
				toAdd := s[startIndex:startIndex+1].printableTree(color, secrets, index+1)
				if toAdd != nil {
					ret.Append(*toAdd)
				}
			}
			startIndex++
			continue
		}

		endIndex := startIndex + 1
		//then check for things under the "directory"
		//Determine end of this "branch"
		for ; endIndex < len(s); endIndex++ {
			thisSplit := strings.Split("/"+s[endIndex].Path, "/")
			if thisSplit[index+1] != groupWord {
				break
			}
		}

		toAdd := s[startIndex:endIndex].printableTree(color, secrets, index+1)
		if toAdd != nil {
			ret.Append(*toAdd)
		}

		startIndex = endIndex
	}

	return ret
}

type treeWorker struct {
	vault  *Vault
	orders *workQueue
	errors chan error
	opts   TreeOpts
}

func (w *treeWorker) work() {
	var err error
	handleError := func() {
		w.orders.Close()
		w.errors <- err
		//This will decrement the awake counter and exit
		//Doesn't actually Pop because we called Close
		w.orders.Pop()
	}

	order, done := w.orders.Pop()
	for !done {
		var answer []secretTree
		var toAppend []secretTree
		for _, op := range []struct {
			code uint16
			fn   func(secretTree) ([]secretTree, error)
		}{
			{opTypeGet, w.workGet},
			{opTypeList, w.workList},
			{opTypeMounts, w.workMounts},
			{opTypeVersions, w.workVersions},
			{opTypeGetLatest, w.workGetLatest},
		} {
			if order.operation&op.code == opTypeNone {
				continue
			}
			toAppend, err = op.fn(*order.insertInto)
			if err != nil {
				break
			}
			//toAppend can be nil if a get was issued on a destroyed node
			// or if it attempted to access a node that was listable but
			// itself not accessible
			if toAppend != nil {
				answer = append(answer, toAppend...)
			}
		}
		if err != nil {
			handleError()
			return
		}

		for i := range answer {
			answer[i].MountVersion, err = w.vault.MountVersion(answer[i].Name)
			if err != nil {
				handleError()
				return
			}
		}

		order.insertInto.Branches = append(order.insertInto.Branches, answer...)
		for i, node := range order.insertInto.Branches {
			w.orders.Push(&workOrder{
				insertInto: &(order.insertInto.Branches[i]),
				operation:  node.getWorkType(w.opts),
			})
		}

		order, done = w.orders.Pop()
	}

	w.errors <- nil
}

func (w *treeWorker) workList(t secretTree) ([]secretTree, error) {
	path := strings.TrimSuffix(t.Name, "/")
	list, err := w.vault.List(path)
	if err != nil {
		//IsNotFound: This is most likely because a mount exists but has no secrets
		//in it yet Probably shouldn't err
		//
		//IsForbidden: This is because you were able to list the contents of a path
		// that this path is contained in, but you do not have the permissions to
		// list this path.
		if vaultkv.IsForbidden(err) {
			w.opts.noteSkippedForbidden()
			return nil, nil
		}
		if IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}

	ret := []secretTree{}

	//This is what happens when you list a mount point which has a secret
	// at its root. We end up detecting it twice. This will ignore finding it
	// out of the list so we only find it once.
	if len(list) > 0 && list[0] == "" {
		list = list[1:]
	}
	for _, l := range list {
		t := treeTypeSecret
		if strings.HasSuffix(l, "/") {
			t = treeTypeDir
		}
		ret = append(ret, secretTree{
			Name: strings.TrimRight(path, "/") + "/" + l,
			Type: t,
		})
	}

	return ret, nil
}

func (w *treeWorker) workGet(t secretTree) ([]secretTree, error) {
	if t.Destroyed {
		return nil, nil
	}
	path := t.Name
	var err error

	if t.Deleted && !w.opts.GetDeletedVersions {
		return nil, nil
	}
	if t.Deleted {
		err = w.vault.Undelete(EncodePath(path, "", uint64(t.Version)))
		if err != nil {
			return nil, err
		}
	}

	s, err := w.vault.Read(EncodePath(path, "", uint64(t.Version)))
	//For v1 backends, this is the first non-list Vault access; for v2
	// backends, workVersions already read the metadata, but a policy can
	// grant metadata and deny the data read separately, so this is where
	// that denial first shows up. Either way, a path we could list but
	// cannot read is skipped rather than aborting the whole walk.
	if err != nil {
		if vaultkv.IsForbidden(err) {
			w.opts.noteSkippedForbidden()
			return nil, nil
		}
		return nil, err
	}

	if t.Deleted {
		err = w.vault.client.Delete(path, &vaultkv.KVDeleteOpts{Versions: []uint{t.Version}})
		if err != nil {
			return nil, err
		}
	}

	version := t.Version
	//If this is a v1 backend, the parent would be a secret node without a version
	if version == 0 {
		version = 1
	}

	ret := []secretTree{}
	for _, key := range s.Keys() {
		//Encode both halves so a literal ':', '^' or '\' in either survives
		// the joined node name; Basename recovers the key with ParsePath.
		// Escaping only the key is not enough: a path ending in a backslash
		// would make the joining colon itself look escaped, and the key
		// would come back empty.
		ret = append(ret, secretTree{
			Name:    EncodePath(path, key, 0),
			Type:    treeTypeKey,
			Value:   string(s.data[key]),
			Version: version,
			Deleted: t.Deleted,
		})
	}

	return ret, nil
}

func (w *treeWorker) workMounts(_ secretTree) ([]secretTree, error) {
	mounts, err := w.vault.KVMounts()
	if err != nil {
		return nil, err
	}

	ret := []secretTree{}
	for _, mount := range mounts {
		//Handle the case in which a mount has a secret at its root
		_, err = w.vault.Read(mount)
		switch {
		case err == nil:
			ret = append(ret, secretTree{
				Name: mount,
				Type: treeTypeSecret,
			})
		case IsNotFound(err):
		case vaultkv.IsForbidden(err):
			//A token holding no read on a mount ended the walk of the whole
			// Vault, so a Vault with one mount the token could not read had
			// nothing safe could say about the mounts it could. The walk skips
			// what it cannot read everywhere else, and this read is a question
			// about a secret that most likely is not there at all, so it is not
			// counted as a skip: the mount is counted where its listing is
			// denied, once, rather than twice for the one mount.
		default:
			return nil, err
		}

		ret = append(ret, secretTree{
			Name: mount + "/",
			Type: treeTypeDir,
		})
	}

	return ret, nil
}

// workGetLatest reads the newest live version of a v2 secret in one
// request. Anything but a clean read falls back to the metadata flow, so
// what the walk reports for deleted, destroyed, empty-keyed, or
// forbidden secrets does not change; only the all-alive common case is
// answered in one request.
func (w *treeWorker) workGetLatest(t secretTree) ([]secretTree, error) {
	if t.MountVersion != 2 {
		return w.workVersions(t)
	}
	s, meta, err := w.vault.readLatestWithMeta(t.Name)
	if err != nil {
		return w.workVersions(t)
	}

	version := secretTree{
		Name:    t.Name,
		Type:    treeTypeVersion,
		Version: meta.Version,
		fetched: true,
	}
	for _, key := range s.Keys() {
		version.Branches = append(version.Branches, secretTree{
			Name:    EncodePath(t.Name, key, 0),
			Type:    treeTypeKey,
			Value:   string(s.data[key]),
			Version: meta.Version,
		})
	}
	return []secretTree{version}, nil
}

func (w *treeWorker) workVersions(t secretTree) ([]secretTree, error) {
	path := t.Name
	//If we've gotten this far, we know that this secret exists if the backend is v1
	// and a v1 backend can only have one version
	if t.MountVersion != 2 {
		return []secretTree{
			{
				Name:    t.Name,
				Type:    treeTypeVersion,
				Version: 1,
			},
		}, nil
	}

	versions, err := w.vault.Versions(path)
	//For v2 backends, this is the first non-list Vault access.
	// If we're unable to get a path that we could list because of permissions,
	// don't explode.
	if err != nil {
		if t.MountVersion == 2 && vaultkv.IsForbidden(err) {
			w.opts.noteSkippedForbidden()
			return nil, nil
		}
		return nil, err
	}

	ret := []secretTree{}
	for i := range versions {
		ret = append(ret, secretTree{
			Name:      t.Name,
			Type:      treeTypeVersion,
			Version:   versions[i].Version,
			Deleted:   versions[i].Deleted,
			Destroyed: versions[i].Destroyed,
		})
	}

	if !w.opts.FetchAllVersions && len(ret) > 0 {
		ret = ret[len(ret)-1:]
	}

	return ret, nil
}

// ValueSearchOpts tunes what FindValueMatches searches and what it reports.
type ValueSearchOpts struct {
	//ShowKeys reports each matching key of a secret rather than the path of
	// the secret alone.
	ShowKeys bool
	//AllVersions searches every readable version of each secret rather than
	// only the newest live one, and names the version each match came from.
	AllVersions bool
	//Deleted searches versions that have been deleted, by undeleting each
	// one, reading it, and deleting it again. Destroyed versions are gone
	// for good and are never searched.
	Deleted bool
}

// FindValueMatches walks each of the given paths and reports the secrets
// containing any of targetValues, compared exactly and case-sensitively
// against whole stored values. With ShowKeys, each match is rendered as
// escaped path:key exactly as Secrets.Paths() renders keyed entries;
// otherwise the path of each matching secret is reported once.
//
// Only the newest live version of a secret is searched unless AllVersions
// is set, which searches the whole readable history and appends ^version to
// every match, so that a match in a superseded version can be told from one
// in the current value and read back as printed. Versions the walk cannot
// read — deleted and destroyed ones — are searched in neither mode, since
// reading them would mean writing to the Vault.
//
// Results sort by PathLessThan on path, then by version, then bytewise by
// key. skipped counts the subtrees the walk dropped because Vault denied
// access to them. Walk errors are accumulated per path and returned joined,
// alongside whatever results the remaining paths produced.
func (v *Vault) FindValueMatches(paths []string, targetValues []string, opts ValueSearchOpts) (results []string, skipped uint64, err error) {
	valueSet := make(map[string]bool, len(targetValues))
	for _, value := range targetValues {
		valueSet[value] = true
	}

	type valueMatch struct {
		path, key string
		version   uint64
	}
	var (
		skipCount  atomic.Uint64
		matches    []valueMatch
		seenSecret = map[string]bool{}
	)

	for _, path := range paths {
		secrets, cerr := v.ConstructSecrets(path, TreeOpts{
			FetchKeys:           true,
			FetchAllVersions:    opts.AllVersions,
			GetDeletedVersions:  opts.Deleted,
			AllowDeletedSecrets: opts.Deleted,
			SkippedForbidden:    &skipCount,
		})
		if cerr != nil {
			err = errors.Join(err, fmt.Errorf("%s: %w", path, cerr))
			continue
		}

		for _, secret := range secrets {
			if seenSecret[secret.Path] {
				continue
			}
			seenSecret[secret.Path] = true
			//ConstructSecrets purges zero-version entries; guard the index anyway
			if len(secret.Versions) == 0 {
				continue
			}

			versions := secret.Versions
			if !opts.AllVersions {
				versions = versions[len(versions)-1:]
			}

			for _, version := range versions {
				//Without Deleted the walk fetched no data for a version it
				// could not read, so a deleted or destroyed one compares
				// against nothing anyway; skipping it by state says so
				// outright. With Deleted the walk undeleted and read them, and
				// a destroyed version stays empty either way.
				if !opts.Deleted && version.State != SecretStateAlive {
					continue
				}

				//Version 0 renders no ^suffix, which is what a search of the
				// current value alone should print. Once more than the current
				// value is in play, naming the version is what tells a match on
				// a superseded or deleted one apart from a live match.
				var number uint64
				if opts.AllVersions || opts.Deleted {
					number = uint64(version.Number)
				}

				data := version.Data
				for _, key := range data.Keys() {
					if !valueSet[data.Get(key)] {
						continue
					}
					matches = append(matches, valueMatch{path: secret.Path, key: key, version: number})
					if !opts.ShowKeys {
						break
					}
				}
			}
		}
	}

	sort.Slice(matches, func(i, j int) bool {
		if matches[i].path != matches[j].path {
			return PathLessThan(matches[i].path, matches[j].path)
		}
		if matches[i].version != matches[j].version {
			return matches[i].version < matches[j].version
		}
		return matches[i].key < matches[j].key
	})

	results = make([]string, 0, len(matches))
	for _, match := range matches {
		key := ""
		if opts.ShowKeys {
			key = match.key
		}
		results = append(results, EncodePath(match.path, key, match.version))
	}

	return results, skipCount.Load(), err
}
