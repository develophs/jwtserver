package com.cos.sjwt.config.jwt;

public interface JwtProperties {
	String SECRET = "secret";
	int EXPIRATION_TIME = 60000; //10분
	String TOKEN_PREFIX = "Bearer ";
	String HEADER_STRING = "Authorization";
}
