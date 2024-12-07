package com.application.authentication.repository;


import com.application.authentication.entity.Role;
import com.application.authentication.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    /**
     * Finds a user by their username.
     *
     * @param username the username of the user to find.
     * @return the {@link User} entity with the specified username, or {@code null} if no user is found.
     */
    User findByUsername(String username);
}
