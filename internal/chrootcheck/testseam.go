package chrootcheck

// This file exposes the userLookup seam to tests in the _test package
// without leaking the unexported `userInfo` type. The published shape
// (UserInfoForTest) is a transparent value type that the production code
// converts back into the unexported userInfo internally.
//
// Production callers MUST NOT use these — they are an explicit test
// surface and any production usage is a bug. (No CI guard enforces this
// today; the file naming convention `testseam.go` is the documentation.)

// UserInfoForTest is the test-visible mirror of the unexported userInfo
// shape. Tests construct values of this type and pass them through
// SetUserLookupForTest.
type UserInfoForTest struct {
	Name string
	UID  uint32
	GID  uint32
}

// SetUserLookupForTest swaps the package-level userLookup seam for a test
// stub. The supplied closure receives the username and must return either
// a deterministic UserInfoForTest or an error. Pair every call with
// `t.Cleanup(chrootcheck.ResetUserLookupForTest)` so parallel/serial
// runs of other tests don't inherit the stub.
func SetUserLookupForTest(stub func(name string) (UserInfoForTest, error)) {
	userLookup = func(name string) (*userInfo, error) {
		u, err := stub(name)
		if err != nil {
			return nil, err
		}
		return &userInfo{Name: u.Name, UID: u.UID, GID: u.GID}, nil
	}
}

// ResetUserLookupForTest restores the production userLookup (os/user.Lookup
// path). Call inside a t.Cleanup after SetUserLookupForTest.
func ResetUserLookupForTest() {
	userLookup = lookupOSUser
}
