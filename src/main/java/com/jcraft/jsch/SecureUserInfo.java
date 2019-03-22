package com.jcraft.jsch;

public interface SecureUserInfo extends UserInfo {
	byte[] getSecurePassword();
}
