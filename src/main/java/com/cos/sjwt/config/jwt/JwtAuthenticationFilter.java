package com.cos.sjwt.config.jwt;

import java.io.IOException;
import java.util.Date;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.cos.sjwt.config.auth.PrincipalDetails;
import com.cos.sjwt.model.User;
import com.fasterxml.jackson.core.exc.StreamReadException;
import com.fasterxml.jackson.databind.DatabindException;
import com.fasterxml.jackson.databind.ObjectMapper;

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
			try {
				ObjectMapper om = new ObjectMapper();
				User user = om.readValue(request.getInputStream(),User.class);
				System.out.println(user);
				
				UsernamePasswordAuthenticationToken authenticationToken =
						new UsernamePasswordAuthenticationToken(user.getUsername(),user.getPassword());
				
				//PrincipalDetailsService의 loadUserByUsername()함수가 실행된다.
				//토큰을 통해 로그인을 시도해보고 로그인이 성공하면 authentication이 생성
				//DB에 있는 username과 password가 일치한다.
				Authentication authentication = authenticationManager.authenticate(authenticationToken);
				
				PrincipalDetails principalDetails = (PrincipalDetails)authentication.getPrincipal();
				
				//값이 존재하면 로그인이 정상적으로 됐다.
				System.out.println("로그인 완료됨 : " + principalDetails.getUser().getUsername()); 
				
				//리턴 후 authentication 객체가 session영역에 저장된다.
				//리턴의 이유는 권한 관리를 security가 대신 해주기 때문에 편하려고
				//굳이 JWT 토큰을 사용하면서 세션을 만들 이유가 없다.
				//권한 처리때문에 session에 넣어준다.
				return authentication;
			} catch (StreamReadException e) {
				e.printStackTrace();
			} catch (DatabindException e) {
				e.printStackTrace();
			} catch (IOException e) {
				e.printStackTrace();
			}
		
		// 2. 정상인지 로그인 시도를 해본다.
		// authenticationManager로 로그인 시도하면 
		// PrincipalDetailsService가 호출 loadUserBuUsername() 함수 실행
		
		// 3. PrincipalDetails를 세션에 담고 -> 세션에 안담으면 권한관리가 안된다.
		// 세션에 담겨있어야 시큐리티가 권한 관리를 해준다.(권한 관리를 위해)
		
		// 4. JWT토큰을 만들어서 응답해주면된다.
		return null;
	}
	
	//attemptAuthentication 실행 후 인증이 정상적으로 되었으면
	//successfulAuthentication 메서드가 실행된다.
	//여기서 JWT토큰을 만들어서 request요청한 사용자에게 JWT토큰을 response해주면된다.
	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
			Authentication authResult) throws IOException, ServletException {
		System.out.println("successfulAuthentication 실행됨 : 인증이 완료되었다는 뜻.");
		
		PrincipalDetails principalDetails = (PrincipalDetails)authResult.getPrincipal();
		
		//RSA방식이 아니라 Hash암호방식
		String jwtToken = JWT.create()
				.withSubject(principalDetails.getUsername())
				.withExpiresAt(new Date(System.currentTimeMillis()+JwtProperties.EXPIRATION_TIME))
				.withClaim("id",principalDetails.getUser().getId())
				.withClaim("username", principalDetails.getUser().getUsername())
				.sign(Algorithm.HMAC512(JwtProperties.SECRET));
		System.out.println(jwtToken);
		response.addHeader("Authorization", "Bearer " + jwtToken);
		//생성한 토큰이 유효한지 판단하는 필터를 생성해야한다.
	}
	

}
