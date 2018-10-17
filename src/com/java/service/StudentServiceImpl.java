package com.java.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;

import com.java.dto.Student;
import com.java.exception.DatabaseException;
import com.java.repository.StudentRepository;

@Service
public class StudentServiceImpl implements StudentService {

	@Autowired
	@Qualifier("rep2")
	private StudentRepository repository;
	
	@Override
	public void addStudent(Student student) throws DatabaseException {
		
		repository.addStudent(student);
	}

	@Override
	public void updateStudent(Student student) {
		// TODO Auto-generated method stub

	}

	@Override
	public void deleteStudent(Student student) {
		// TODO Auto-generated method stub

	}

	@Override
	public Student getStudentById(int id) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public List<Student> getStudents() {
		// TODO Auto-generated method stub
		return null;
	}

}
