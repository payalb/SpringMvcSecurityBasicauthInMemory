package com.java.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.ModelAndView;

@Controller
public class StudentControllerOne {
	@RequestMapping("/add")
	public ModelAndView doWork(){
		ModelAndView mv = new ModelAndView("addStudent");
		return mv;
	}

}
