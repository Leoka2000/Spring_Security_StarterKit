package pt.tahvago.repository;

import java.util.Optional;

import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import pt.tahvago.model.AppUser;

@Repository
public interface UserRepository extends CrudRepository<AppUser, Long> {
    Optional<AppUser> findByEmail(String email);

    Optional<AppUser> findByUsername(String username);

    Optional<AppUser> findByVerificationCode(String verificationCode);
}
