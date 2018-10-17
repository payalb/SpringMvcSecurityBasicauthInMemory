package com.java.config;

import javax.sql.DataSource;

import org.apache.tomcat.dbcp.dbcp2.BasicDataSource;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.DependsOn;

@Configuration
public class DatabasePropertyConfig {

	@Value("${jdbc.url}")
	private String url;
	@Value("${jdbc.username}")
	private String username;
	@Value("${jdbc.password}")
	private String password;
	@Value("${jdbc.driverName}")
	private String driverName;
	
	public String getUrl() {
		return url;
	}

	public void setUrl(String url) {
		this.url = url;
	}

	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public String getDriverName() {
		return driverName;
	}

	public void setDriverName(String driverName) {
		this.driverName = driverName;
	}

	@Bean("ds")
	@DependsOn("pr")
	public DataSource getDataSource() {
		BasicDataSource ds= new BasicDataSource();
		ds.setUrl(getUrl());
		System.out.println("url is"+ getUrl());
		ds.setPassword(getPassword());
		ds.setUsername(getUsername());
		ds.setDriverClassName(getDriverName());
		System.out.println("ds is" + ds);
		return ds;
	}
	
}
