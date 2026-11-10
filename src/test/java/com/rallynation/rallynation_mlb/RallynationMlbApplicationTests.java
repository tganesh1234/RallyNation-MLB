package com.rallynation.rallynation_mlb;

import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.rallynation.rallynation_mlb.user.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class RallynationMlbApplicationTests {

	@Autowired
	private MockMvc mockMvc;

	@Autowired
	private UserRepository users;

	@BeforeEach
	void clearUsers() {
		users.deleteAll();
	}

	@Test
	void contextLoads() {
	}

	@Test
	void registrationLoginAndProtectedRequestWork() throws Exception {
		register("fan@example.com");

		String response = mockMvc.perform(post("/api/auth/login")
						.contentType(MediaType.APPLICATION_JSON)
						.content("""
								{"email":"fan@example.com","password":"correct-horse-battery"}
								"""))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.tokenType", is("Bearer")))
				.andReturn()
				.getResponse()
				.getContentAsString();
		Matcher tokenMatcher = Pattern.compile("\"accessToken\":\"([^\"]+)\"").matcher(response);
		assertTrue(tokenMatcher.find());
		String token = tokenMatcher.group(1);

		mockMvc.perform(get("/api/auth/me")
						.header("Authorization", "Bearer " + token))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.email", is("fan@example.com")));
	}

	@Test
	void protectedRequestWithoutTokenIsUnauthorized() throws Exception {
		mockMvc.perform(get("/api/auth/me"))
				.andExpect(status().isUnauthorized());
	}

	@Test
	void malformedTokenIsUnauthorized() throws Exception {
		mockMvc.perform(get("/api/auth/me")
						.header("Authorization", "Bearer not-a-jwt"))
				.andExpect(status().isUnauthorized());
	}

	@Test
	void invalidPasswordIsUnauthorized() throws Exception {
		register("fan@example.com");

		mockMvc.perform(post("/api/auth/login")
						.contentType(MediaType.APPLICATION_JSON)
						.content("""
								{"email":"fan@example.com","password":"incorrect-password"}
								"""))
				.andExpect(status().isUnauthorized())
				.andExpect(jsonPath("$.message", is("Invalid email or password")));
	}

	@Test
	void duplicateEmailIsConflictAndEmailIsCaseInsensitive() throws Exception {
		register("Fan@Example.com");

		mockMvc.perform(post("/api/auth/register")
						.contentType(MediaType.APPLICATION_JSON)
						.content("""
								{"email":"fan@example.com","password":"correct-horse-battery"}
								"""))
				.andExpect(status().isConflict());
	}

	@Test
	void registrationRejectsPasswordsLongerThanBcryptByteLimit() throws Exception {
		mockMvc.perform(post("/api/auth/register")
						.contentType(MediaType.APPLICATION_JSON)
						.content("""
								{"email":"fan@example.com","password":"😀😀😀😀😀😀😀😀😀😀😀😀😀😀😀😀😀😀😀"}
								"""))
				.andExpect(status().isBadRequest());
	}

	@Test
	void registrationStoresOnlyPasswordHash() throws Exception {
		register("fan@example.com");

		var user = users.findByEmail("fan@example.com").orElseThrow();
		String passwordHash = user.getPasswordHash();
		assertNotEquals("correct-horse-battery", passwordHash);
		assertTrue(user.getCreatedAt() != null);
		assertTrue(user.getUpdatedAt() != null);
		assertTrue(!user.getUpdatedAt().isBefore(user.getCreatedAt()));
	}

	private void register(String email) throws Exception {
		mockMvc.perform(post("/api/auth/register")
						.contentType(MediaType.APPLICATION_JSON)
						.content("""
								{"email":"%s","password":"correct-horse-battery"}
								""".formatted(email)))
				.andExpect(status().isCreated());
	}
}
