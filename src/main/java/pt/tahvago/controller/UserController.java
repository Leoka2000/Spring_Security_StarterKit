package pt.tahvago.controller;

import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import pt.tahvago.dto.ChangePasswordDto;
import pt.tahvago.dto.UpdateUserDto;
import pt.tahvago.model.AppUser;
import pt.tahvago.service.JwtService;
import pt.tahvago.service.UserService;

@RequestMapping("/users")
@RestController
public class UserController {
    private static final Logger logger = LoggerFactory.getLogger(UserController.class);
    private final UserService userService;
    private final JwtService jwtService;

    public UserController(UserService userService, JwtService jwtService) {
        this.userService = userService;
        this.jwtService = jwtService;
    }

    @PatchMapping("/me")
    public ResponseEntity<?> updateCurrentUser(@RequestBody UpdateUserDto updateDto) {
        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            if (authentication == null || !authentication.isAuthenticated()) {
                return ResponseEntity.status(401).build();
            }

            AppUser currentUser = (AppUser) authentication.getPrincipal();

            AppUser updatedUser = userService.updateUser(
                    currentUser.getId(),
                    updateDto.getUsername(),
                    updateDto.getEmail());

            String newToken = jwtService.generateToken(updatedUser);

            return ResponseEntity.ok()
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + newToken)
                    .body(Map.of(
                            "user", updatedUser,
                            "token", newToken));
        } catch (ClassCastException e) {
            logger.error("Authentication principal type mismatch", e);
            return ResponseEntity.status(403).build();
        } catch (Exception e) {
            logger.error("Error updating user", e);
            return ResponseEntity.internalServerError()
                    .body(Map.of("error", "Failed to update user"));
        }
    }

    @GetMapping("/me")
    public ResponseEntity<AppUser> authenticatedUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null) {
            return ResponseEntity.status(401).build();
        }

        try {
            AppUser currentUser = (AppUser) authentication.getPrincipal();
            return ResponseEntity.ok(currentUser);
        } catch (ClassCastException e) {
            return ResponseEntity.status(403).build();
        } catch (Exception e) {
            return ResponseEntity.internalServerError().build();
        }
    }

    @PatchMapping("/me/password")
    public ResponseEntity<?> changePassword(@RequestBody ChangePasswordDto dto) {
        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

            if (authentication == null || !authentication.isAuthenticated()) {
                return ResponseEntity.status(401).build();
            }

            AppUser currentUser = (AppUser) authentication.getPrincipal();

            userService.changePassword(
                    currentUser.getId(),
                    dto.getCurrentPassword(),
                    dto.getNewPassword(),
                    dto.getConfirmPassword());

            return ResponseEntity.ok(Map.of("message", "Password changed successfully"));
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        } catch (Exception e) {
            logger.error("Unexpected error during password change", e);
            return ResponseEntity.internalServerError().body(Map.of("error", "Failed to change password"));
        }
    }
}