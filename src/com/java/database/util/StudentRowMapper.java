package com.java.database.util;

import java.sql.ResultSet;
import java.sql.SQLException;

import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Component;

import com.java.dto.Student;

@Component
public class StudentRowMapper implements RowMapper<Student>{

		@Override
		public Student mapRow(ResultSet rs, int rowNum) throws SQLException {
			Student st= new Student();
			st.setName(rs.getString("name"));
			st.setPassword(rs.getString("password"));
			st.setId(rs.getInt("id"));
			return st;
		}
		

}
