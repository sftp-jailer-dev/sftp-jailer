package chrootcheck

import (
	"os/user"
	"strconv"
)

// lookupOSUser wraps os/user.Lookup and converts UID/GID strings into
// uint32 for FileInfo comparison. Isolated in its own file so the test
// override of userLookup stays focused on the chrootcheck domain.
func lookupOSUser(name string) (*userInfo, error) {
	u, err := user.Lookup(name)
	if err != nil {
		return nil, err
	}
	uid, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return nil, err
	}
	gid, err := strconv.ParseUint(u.Gid, 10, 32)
	if err != nil {
		return nil, err
	}
	return &userInfo{Name: u.Username, UID: uint32(uid), GID: uint32(gid)}, nil
}
