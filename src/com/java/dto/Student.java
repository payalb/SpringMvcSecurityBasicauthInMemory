package com.java.dto;

public class Student {
	
	private int id;
	private String name;
	private String password;
	
	public int getId() {
		return id;
	}

	public void setId(int id) {
		this.id = id;
	}

	public Student(int id, String name, String password) {
		super();
		this.id = id;
		this.name = name;
		this.password = password;
	}

	public String getName() {
		return name;
	}
	public void setName(String name) {
		this.name = name;
	}
	public String getPassword() {
		return password;
	}
	public void setPassword(String password) {
		this.password = password;
	}

	public Student() {
		super();
		// TODO Auto-generated constructor stub
	}

}
