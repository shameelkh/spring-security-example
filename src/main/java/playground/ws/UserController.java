package playground.ws;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;
import playground.db.User;
import playground.service.MyUserDetailsService;

@RestController
public class UserController {

    @Autowired
    MyUserDetailsService userDetailsService;

//    @RequestMapping(value = "/login", method = RequestMethod.POST)
//    public ResponseEntity login(@RequestBody LoginCredentials loginCredentials) {
//
//        return new ResponseEntity("Success", HttpStatus.ACCEPTED);
//    }

    @RequestMapping(value = "/sign-up", method = RequestMethod.POST)
    public ResponseEntity signUp(@RequestBody User user) {
        userDetailsService.signUpUser(user);
        return new ResponseEntity(HttpStatus.ACCEPTED);
    }
}
