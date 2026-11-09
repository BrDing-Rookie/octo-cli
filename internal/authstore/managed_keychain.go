package authstore

func systemKeychain() managedKeychain {
	return unavailableKeychain{}
}
