package com.java.bootstrap;

import javax.annotation.PostConstruct;
import javax.annotation.PreDestroy;

import org.springframework.beans.factory.DisposableBean;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import com.java.dto.Student;
import com.java.exception.DatabaseException;
import com.java.repository.StudentRepository;
@Profile("test")
@Component
public class DataInitializer implements InitializingBean, DisposableBean{
	
	@Autowired //AutowiredBeanPostProcessor
	StudentRepository rep;
	
	@PostConstruct //To enable this: CommonAnnotationBeanPostProcessor
	public void init() throws DatabaseException {
		System.out.println("inti called!!");
		rep.addStudent(new Student(1, "payal","payal"));
	}
	@Override
	public void afterPropertiesSet() throws Exception {
		System.out.println("after property set called called!!");
		rep.addStudent(new Student(2,"ritu","ritu"));
		
	}

	@Override
	public void destroy() throws Exception {
		rep.deleteStudent(new Student(2,"ritu","ritu"));
		
	}
	
	@PreDestroy
	public void destroy1() {
		rep.deleteStudent(new Student(1, "payal","payal"));
	}
}
