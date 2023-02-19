package com.cos.sjwt.config.jwt;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import lombok.RequiredArgsConstructor;


// 스프링 시큐리티에 UsernamePasswordAuthenticationFilter가 존재한다.
// /login 요청해서 username, password 전송하면(post)
// UsernamePasswordAuthenticationFilter 동작
// but, formLogin.disable해서 작동을 안한다.

@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter{

	private final AuthenticationManager authenticationManager;

	// /login 요청을 하면 로그인 시도를 위해서 실행되는 함수
	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException {
		System.out.println("JwtAuthenticationFilter : 로그인 시도중");
		
		// 1. username, password 받아서
		
		// 2. 정상인지 로그인 시도를 해본다.
		// authenticationManager로 로그인 시도하면 
		// PrincipalDetailsService가 호출 loadUserBuUsername() 함수 실행
		
		// 3. PrincipalDetails를 세션에 담고 -> 세션에 안담으면 권한관리가 안된다.
		// 세션에 담겨있어야 시큐리티가 권한 관리를 해준다.(권한 관리를 위해)
		
		// 4. JWT토큰을 만들어서 응답해주면된다.
		return super.attemptAuthentication(request, response);
	}
	

}
