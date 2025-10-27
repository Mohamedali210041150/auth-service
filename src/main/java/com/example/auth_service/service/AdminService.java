package com.example.auth_service.service;

import com.example.auth_service.model.entity.Admin;
import com.example.auth_service.repository.AdminRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class AdminService {

    private final AdminRepository adminRepository;
    private final PasswordEncoder passwordEncoder;

    public AdminService(AdminRepository adminRepository, PasswordEncoder passwordEncoder) {
        this.adminRepository = adminRepository;
        this.passwordEncoder = passwordEncoder;
    }

    public Admin registerAdmin(String name, String email, String rawPassword) {
        // Check if admin already exists
        Optional<Admin> existingAdmin = adminRepository.findByEmail(email);
        if (existingAdmin.isPresent()) {
            throw new RuntimeException("Admin with email " + email + " already exists");
        }
        
        String hashedPassword = passwordEncoder.encode(rawPassword);
        Admin admin = new Admin(name, email, hashedPassword);
        return adminRepository.save(admin);
    }

    public Admin authenticateAdmin(String email, String rawPassword) {
        Optional<Admin> adminOpt = adminRepository.findByEmail(email);
        if (adminOpt.isPresent()) {
            Admin admin = adminOpt.get();
            if (passwordEncoder.matches(rawPassword, admin.getPassword())) {
                return admin;
            }
        }
        return null;
    }

    public Admin findByEmail(String email) {
        return adminRepository.findByEmail(email).orElse(null);
    }
}