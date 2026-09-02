package policy

import (
	"time"

	"github.com/sagnikhaldar/gin-recon/internal/config"
	"github.com/sagnikhaldar/gin-recon/internal/model"
)

// exceptionApplies reports whether any of exceptions both selects route and
// has not yet expired. Expiry is evaluated in UTC per
// docs/configuration-contract.md: an exception expiring "2026-01-01" covers
// through the end of that day UTC, so it is compared as "before the
// following midnight" rather than "before midnight of that day."
func exceptionApplies(route model.Route, exceptions []config.Exception, now time.Time) bool {
	nowUTC := now.UTC()
	for _, exc := range exceptions {
		expiry, err := time.ParseInLocation("2006-01-02", exc.Expires, time.UTC)
		if err != nil {
			continue // config.Validate already rejects malformed dates; defensive only
		}
		if !nowUTC.Before(expiry.AddDate(0, 0, 1)) {
			continue // expired
		}
		if matchesSelector(route, exc.Selector) {
			return true
		}
	}
	return false
}
