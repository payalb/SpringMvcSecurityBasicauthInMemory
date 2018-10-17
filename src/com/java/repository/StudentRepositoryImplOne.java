/*package com.java.repository;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import com.java.config.DatabasePropertyConfig;
//java.sql package: jdbc classes
import com.java.dto.Student;
import com.java.exception.DatabaseException;

@Repository("rep1")
public class StudentRepositoryImplOne implements StudentRepository {

	@Autowired
	private DatabasePropertyConfig util;

	@Override
	public int addStudent(Student student) throws DatabaseException {
		int id= -1;
		try (
			Connection conn = util.getConnection();
			Statement st = conn.createStatement();
			){
			st.executeUpdate("insert into student values (idGenerator.nextval , " + student.getName() + " ,"
					+ student.getPassword() + ")");
			ResultSet set=st.executeQuery("select idGenerator.currval from dual");
			while(set.next()) {
				 id=set.getInt("idGenerator.currval");
			}
			set.close();
		} catch (SQLException e) {
			throw new DatabaseException("Unable to insert record into db"+ e.getMessage());
		}
		return id;
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
*/