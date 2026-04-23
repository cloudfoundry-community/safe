package main

import (
	"fmt"
	"regexp"
	"strconv"
	"time"
)

func duration(s string) (time.Duration, error) {
	re := regexp.MustCompile(`^(\d+)([HhDdMmYy])$`)
	if m := re.FindStringSubmatch(s); m != nil {
		v, err := strconv.ParseUint(m[1], 10, 64)
		if err != nil {
			return 0, err
		}

		// Check for overflow before multiplication. The max int64 is computed
		// via an unsigned-shifted all-ones mask; using ^time.Duration(0) (a
		// signed int64 -1) with arithmetic right-shift would yield -1, making
		// every non-zero value look "too large".
		const maxDuration = time.Duration(^uint64(0) >> 1)
		
		switch m[2] {
		case "H", "h":
			if v > uint64(maxDuration/time.Hour) {
				return 0, fmt.Errorf("duration overflow: %d hours is too large", v)
			}
			return time.Hour * time.Duration(v), nil
		case "D", "d":
			hoursPerDay := uint64(24)
			if v > uint64(maxDuration/time.Hour)/hoursPerDay {
				return 0, fmt.Errorf("duration overflow: %d days is too large", v)
			}
			// G115: Safe conversion after overflow check
			product := hoursPerDay * v
			if product > uint64(maxDuration/time.Hour) {
				return 0, fmt.Errorf("duration overflow: calculated hours too large")
			}
			return time.Hour * time.Duration(product), nil
		case "M", "m":
			hoursPerMonth := uint64(24 * 30)
			if v > uint64(maxDuration/time.Hour)/hoursPerMonth {
				return 0, fmt.Errorf("duration overflow: %d months is too large", v)
			}
			// G115: Safe conversion after overflow check
			product := hoursPerMonth * v
			if product > uint64(maxDuration/time.Hour) {
				return 0, fmt.Errorf("duration overflow: calculated hours too large")
			}
			return time.Hour * time.Duration(product), nil
		case "Y", "y":
			hoursPerYear := uint64(24 * 365)
			if v > uint64(maxDuration/time.Hour)/hoursPerYear {
				return 0, fmt.Errorf("duration overflow: %d years is too large", v)
			}
			// G115: Safe conversion after overflow check
			product := hoursPerYear * v
			if product > uint64(maxDuration/time.Hour) {
				return 0, fmt.Errorf("duration overflow: calculated hours too large")
			}
			return time.Hour * time.Duration(product), nil
		}
	}
	return 0, fmt.Errorf("unrecognized time spec '%s'", s)
}

func uniq(l []string) []string {
	seen := make(map[string]bool)
	u := make([]string, 0)

	for _, s := range l {
		if !seen[s] {
			u = append(u, s)
		}
		seen[s] = true
	}

	return u
}
