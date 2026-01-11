package com.example.security;

import java.time.Instant;

import jakarta.persistence.*;

@Entity
@Table(name= "refresh_tokens")
public class RefreshTokenEntity {
	
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;
	
	@Column(unique = true, nullable = false, length=512)
	private String token;										//Opaque randon string (Consider hashing in prod)
	
	@Column(nullable = false)
	private String username;
	
	@Column(nullable = false)
	private Instant createdAt;
	
	@Column(nullable = false)
	private Instant expiresAt;
	
	@Column(nullable = false)
	private boolean revoked = false;
	
	private String replacedByToken;    // for rotation chain 
		
	private String userAgent;			//optional auditing
	private String ip;					// optional auditing
	
	
	/**
	 * @return the id
	 */
	public Long getId() {
		return id;
	}
	/**
	 * @param id the id to set
	 */
	public void setId(Long id) {
		this.id = id;
	}
	/**
	 * @return the token
	 */
	public String getToken() {
		return token;
	}
	/**
	 * @param token the token to set
	 */
	public void setToken(String token) {
		this.token = token;
	}
	/**
	 * @return the username
	 */
	public String getUsername() {
		return username;
	}
	/**
	 * @param username the username to set
	 */
	public void setUsername(String username) {
		this.username = username;
	}
	/**
	 * @return the createdAt
	 */
	public Instant getCreatedAt() {
		return createdAt;
	}
	/**
	 * @param createdAt the createdAt to set
	 */
	public void setCreatedAt(Instant createdAt) {
		this.createdAt = createdAt;
	}
	/**
	 * @return the expiresAt
	 */
	public Instant getExpiresAt() {
		return expiresAt;
	}
	/**
	 * @param expiresAt the expiresAt to set
	 */
	public void setExpiresAt(Instant expiresAt) {
		this.expiresAt = expiresAt;
	}
	/**
	 * @return the revoked
	 */
	public boolean isRevoked() {
		return revoked;
	}
	/**
	 * @param revoked the revoked to set
	 */
	public void setRevoked(boolean revoked) {
		this.revoked = revoked;
	}
	/**
	 * @return the replacedByToken
	 */
	public String getReplacedByToken() {
		return replacedByToken;
	}
	/**
	 * @param replacedByToken the replacedByToken to set
	 */
	public void setReplacedByToken(String replacedByToken) {
		this.replacedByToken = replacedByToken;
	}
	/**
	 * @return the userAgent
	 */
	public String getUserAgent() {
		return userAgent;
	}
	/**
	 * @param userAgent the userAgent to set
	 */
	public void setUserAgent(String userAgent) {
		this.userAgent = userAgent;
	}
	/**
	 * @return the ip
	 */
	public String getIp() {
		return ip;
	}
	/**
	 * @param ip the ip to set
	 */
	public void setIp(String ip) {
		this.ip = ip;
	}
	

}
