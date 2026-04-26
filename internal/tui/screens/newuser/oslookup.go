// oslookup.go isolates the os/user.LookupId seam used for UID-collision
// checks during validation. Pattern mirrors internal/chrootcheck/oslookup.go
// — the production function lives in its own file so the test override stays
// focused and discoverable. Tests swap via SetUserLookupForTest on the
// Model.
package newuser

import (
	"os/user"
	"strconv"
)

// defaultUserLookup is the production implementation of userLookupFn —
// returns true iff a user with the given UID exists in /etc/passwd (via
// os/user.LookupId, which goes through nsswitch). NSS lookup failure or
// "user not found" both translate to false (the modal proceeds and useradd
// will surface any deeper error).
func defaultUserLookup(uid int) bool {
	_, err := user.LookupId(strconv.Itoa(uid))
	return err == nil
}
