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

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class MyFilter3 implements Filter{

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		
		log.info("Filter3실행");
		
		HttpServletRequest req = (HttpServletRequest) request;
		HttpServletResponse res = (HttpServletResponse) response;
		
		// id,pw 정상적으로 들어와서 로그인이 완료되면
		// 토큰을 만들어주고 응답을 해준다.
		// 요청할 때 마다 header - Authorization의 value값으로 토큰을 가지고온다.
		// 토큰이 넘어오면 이 토큰이 내가 만든 토큰이 맞는지 검증해야한다.(RSA, HS256)
		if("POST".equals(req.getMethod())) {
			String headerAuth = req.getHeader("Authorization");
			log.info("POST.headerAuth = {}",headerAuth);
			if("hello".equals(headerAuth)) {
				log.info("토큰값일치 필터 체인 진행");
				chain.doFilter(req, res);
			} else {
				log.info("토큰값일치 하지 않아 중단.");
			}
		}
		
	}

	
}
