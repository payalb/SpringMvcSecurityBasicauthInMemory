package com.java.config;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@Configuration
@EnableWebSecurity
public class SpringSecurityConfig extends WebSecurityConfigurerAdapter {

	@Autowired
	DataSource ds;

	@Autowired
	public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
		/*
		 * auth.jdbcAuthentication().dataSource(ds)
		 * .usersByUsernameQuery("select username, password from users where username = ?"
		 * )
		 * .authoritiesByUsernameQuery("select  username, authority from roles where username = ?"
		 * ); System.out.println("fired!" + ds);
		 */
		auth.inMemoryAuthentication().withUser("payal").password("$2a$12$Wdr6XE0s1m2gZJtSs.hKn.Ubiv83.9UnfgASOgo7FUvYj4nU.fApS").roles("USER").and().passwordEncoder(new BCryptPasswordEncoder(12));
	}

	@Override
	public void configure(HttpSecurity http) throws Exception {
		// Spring Security 4 automatically prefixes any role with ROLE_.
		http.authorizeRequests().antMatchers("/").permitAll().anyRequest().hasAnyAuthority("ROLE_ADMIN", "ROLE_USER")
				.anyRequest().authenticated().and().httpBasic();

	}

}
