package com.java.repository;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

import com.java.database.util.StudentRowMapper;
//java.sql package: jdbc classes
import com.java.dto.Student;
import com.java.exception.DatabaseException;

@Repository("rep2a")
public class StudentRepositoryImplTwo implements StudentRepository {

	@Autowired JdbcTemplate template;
	@Autowired StudentRowMapper mapper;

	@Override
	public int addStudent(Student student) throws DatabaseException {
			template.update("insert into student (name, password) values ("+ student.getName() + " ,"
					+ student.getPassword() + ")");
		return -1;
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
		return template.queryForObject("select * from student where id =?", new Object[] {1},mapper);
	}

	@Override
	public List<Student> getStudents() {
		// TODO Auto-generated method stub
		return null;
	}

}
