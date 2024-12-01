package com.ali.springSecurity.Student;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.List;

@RestController
@RequestMapping("user")
public class StudentController {

    List<Student> studentsList = new ArrayList<>(List.of(
            new Student(1,"ali",40),
            new Student(2,"abca",30)
    ));

    @GetMapping("/students")
    public List<Student> getStudentsList(){
        return studentsList;
    }



    @PostMapping("/students")
    public Student addStudent(@RequestBody Student student){
        studentsList.add(student);
        return student;
    }

}
