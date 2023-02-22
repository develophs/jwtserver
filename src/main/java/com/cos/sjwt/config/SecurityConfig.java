package com.cos.sjwt.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import org.springframework.web.filter.CorsFilter;

import com.cos.sjwt.config.jwt.JwtAuthenticationFilter;
import com.cos.sjwt.config.jwt.JwtAuthorizationFilter;
import com.cos.sjwt.filter.MyFilter3;
import com.cos.sjwt.repository.UserRepository;

import lombok.RequiredArgsConstructor;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter{

	private final CorsFilter corsFilter;
	private final UserRepository userRepository;
	
	@Bean
	public BCryptPasswordEncoder bCryptPasswordEncoder() {
		return new BCryptPasswordEncoder();
	}
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		//시큐리티 필터가 동작하기전에 JWT필터를 먼저 실행시킨다.
		http.addFilterBefore(new MyFilter3(), SecurityContextPersistenceFilter.class);
		http.csrf().disable();
		//기존 세션방식을 사용하지 않겠다. 무상태유지. stateless
		http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
		.and()
		//Config클래스에서 설정한 내용을 필터로 등록한다.
		.addFilter(corsFilter)
		//기존 html에서 <form>태그를 이용한 로그인을 하지 않겠다.
		.formLogin().disable()
		//httpBasic을 사용하지 않고, Bearer방식을 사용한다.
		.httpBasic().disable()
		.addFilter(new JwtAuthenticationFilter(authenticationManager())) //AuthenticationManager를 파라미터로 보내야한다.
		.addFilter(new JwtAuthorizationFilter(authenticationManager(),userRepository)) //AuthenticationManager를 파라미터로 보내야한다.
		.authorizeRequests()
		.antMatchers("/api/v1/user/**")
		.access("hasRole('ROLE_USER') or hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
		.antMatchers("/api/v1/manager/**")
		.access("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
		.antMatchers("/api/v1/admin/**")
		.access("hasRole('ROLE_ADMIN')")
		.anyRequest().permitAll();
		
	}
	
}
