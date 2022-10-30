package com.backend.backend.models;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import java.time.Instant;

@Data
@Document
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class RefreshToken {
  @Id
  private String id;
  private User user;
  private String token;
  private Instant expiryDate;

}
