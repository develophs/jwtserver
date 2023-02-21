package com.cos.sjwt.config.jwt;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.cos.sjwt.config.auth.PrincipalDetails;
import com.cos.sjwt.model.User;
import com.cos.sjwt.repository.UserRepository;

// 시큐리티가 filter를 가지고 있는데 그 필터중에 BasicAuthenticationFilter 라는 것이 있다.
// 권한이나 인증이 필요한 특정 주소를 요청했을 때 위 필터를 무조건 타게 되어있다.
// 만약에 권한이 인증이 필요한 주소가 아니라면 이 필터를 안탄다.
public class JwtAuthorizationFilter extends BasicAuthenticationFilter{
	
	private UserRepository userRepository;

	public JwtAuthorizationFilter(AuthenticationManager authenticationManager,UserRepository userRepository) {
		super(authenticationManager);
		this.userRepository =userRepository;
	}
	
	//인증이나 권한이 필요한 주소요청이 있을 때 해당 필터를 타게된다.
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		System.out.println("인증이나 권한이 필요한 주소 요청");
		
		String header  = request.getHeader(JwtProperties.HEADER_STRING);
		System.out.println("header : " + header);
		
		// header가 있는지 확인
		if(header == null || !header.startsWith(JwtProperties.TOKEN_PREFIX)) {
			chain.doFilter(request, response);
			return;
		}
		
		// JWT 토큰을 검증해서 정상적인 사용자인지 확인한다.
		String jwtToken = request.getHeader("Authorization").replace("Bearer ","");
		String username =
				JWT.require(Algorithm.HMAC512("cos")).build().verify(jwtToken).getClaim("username").asString();
		
		// 서명이 정상적으로 작동됨
		if(username != null) {
			User user = userRepository.findByUsername(username);
			
			// 인증은 토큰 검증시 끝. 인증을 하기 위해서가 아닌 스프링 시큐리티가 수행해주는 권한 처리를 위해 
			// 아래와 같이 토큰을 만들어서 Authentication 객체를 강제로 만들고 그걸 세션에 저장!
			
			PrincipalDetails principalDetails = new PrincipalDetails(user);
			// Jwt토큰 서명을 통해서 서명이 정상이면 Authentication을 생성 
			Authentication authentication = new UsernamePasswordAuthenticationToken(principalDetails,//나중에 컨트롤러에서 DI해서 쓸 때 편함
					null,// 패스워드는 모르니까 null처리, 어차피 지금 인증하는게 아니다. 
					principalDetails.getAuthorities());
			
			// 강제로 시큐리티의 세션에 접근하여 Authentication객체를 저장.
			SecurityContextHolder.getContext().setAuthentication(authentication);
		}
		chain.doFilter(request, response);
		
		
	}


}
