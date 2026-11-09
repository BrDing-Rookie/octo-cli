//go:build !darwin

package authstore

func systemKeychain() Keychain {
	return unavailableKeychain{}
}
