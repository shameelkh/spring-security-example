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

    @RequestMapping(value = "/secure-message", method = RequestMethod.GET)
    public ResponseEntity secureMessage() {
        return new ResponseEntity("{\"message\": \"The Secret is Within\"}", HttpStatus.OK);
    }

    @RequestMapping(value = "/sign-up", method = RequestMethod.POST)
    public ResponseEntity signUp(@RequestBody User user) {
        userDetailsService.signUpUser(user);
        return new ResponseEntity(HttpStatus.OK);
    }
}
