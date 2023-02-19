package com.cos.sjwt.filter;

import java.io.IOException;
import java.io.PrintWriter;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


public class MyFilter3 implements Filter{

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		
		HttpServletRequest req = (HttpServletRequest) request;
		HttpServletResponse res = (HttpServletResponse) response;
		
		// id,pw 정삭적으로 들어와서 로그인이 완료되면
		// 토큰을 만들어주고 응답을 해준다.
		// 요청할 때 마다 header - Authorization의 value값으로 토큰을 가지고온다.
		// 토큰이 넘어오면 이 토큰이 내가 만든 토큰이 맞는지 검증해야한다.(RSA, HS256)
		if("POST".equals(req.getMethod())) {
			String headerAuth = req.getHeader("Authorization");
			System.out.println(headerAuth);
			System.out.println("필터3 시큐리티가 동작하기전에 동작해야된다.");
			if("hello".equals(headerAuth)) {
				chain.doFilter(req, res);
			} else {
				PrintWriter out = res.getWriter();
				out.println("인증 안됨");
			}
		}
		
	}

	
}
