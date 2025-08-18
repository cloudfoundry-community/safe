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

		// Check for overflow before multiplication
		const maxDuration = int64(^time.Duration(0) >> 1)
		
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
			return time.Hour * time.Duration(hoursPerDay*v), nil
		case "M", "m":
			hoursPerMonth := uint64(24 * 30)
			if v > uint64(maxDuration/time.Hour)/hoursPerMonth {
				return 0, fmt.Errorf("duration overflow: %d months is too large", v)
			}
			return time.Hour * time.Duration(hoursPerMonth*v), nil
		case "Y", "y":
			hoursPerYear := uint64(24 * 365)
			if v > uint64(maxDuration/time.Hour)/hoursPerYear {
				return 0, fmt.Errorf("duration overflow: %d years is too large", v)
			}
			return time.Hour * time.Duration(hoursPerYear*v), nil
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
