package me.ogq.ocp.hmactest;

import java.net.URI;
import java.time.Instant;
import java.time.ZonedDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Formatter;
import java.util.Optional;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.web.util.UriComponentsBuilder;

public class HMacSigner {

  private static final String CHARSET = "UTF-8";
  private static final String ALGORITHM = "HmacSHA256";

  private static final String SIGNATURE_PARAM = "mac";
  private static final String API_KEY_PARAM = "apiKey";
  private static final String TIME_PARAM = "createdAt";

  private final String apiKey;
  private final byte[] secret;

  public HMacSigner(String apiKey, String base64Secret) {
    this.apiKey = apiKey;
    this.secret = Base64.getDecoder().decode(base64Secret);
  }

  public URI sign(URI uri) {
    UriComponentsBuilder builder = UriComponentsBuilder.fromUri(uri);
    builder.queryParam(TIME_PARAM, ZonedDateTime.now().toEpochSecond());
    builder.queryParam(API_KEY_PARAM, apiKey);

    String mac = generateHash(builder.toUriString());
    builder.queryParam(SIGNATURE_PARAM, mac);
    return builder.build().toUri();
  }

  public boolean validate(URI uri) {
    return isValidTimeParam(uri) && isValidMacParam(uri);
  }

  private String originReq(URI uri) {
    UriComponentsBuilder builder = UriComponentsBuilder.fromUri(uri);
    return builder.replaceQueryParam(SIGNATURE_PARAM).build().toUriString();
  }

  private boolean isValidMacParam(URI uri) {
    String originReq = originReq(uri);
    Optional<String> mac = extract(uri, SIGNATURE_PARAM);
    return mac.map(signed  -> signed.equals(generateHash(originReq))).orElse(false);
  }

  private boolean isValidTimeParam(URI uri) {
    Optional<String> created = extract(uri, TIME_PARAM);
    return created.map(Long::parseLong)
        .map(this::isInTime)
        .orElse(false);
  }

  private boolean isInTime(Long instant) {
    Instant created = Instant.ofEpochSecond(instant);
    Instant begin = Instant.now().minus(5, ChronoUnit.MINUTES);
    Instant end = Instant.now().plus(5, ChronoUnit.MINUTES);
    return created.isAfter(begin) && created.isBefore(end);
  }

  private Optional<String> extract(URI uri, String param) {
    UriComponentsBuilder builder = UriComponentsBuilder.fromUri(uri);
    return Optional.ofNullable(builder.build().getQueryParams().getFirst(param));
  }

  private String generateHash(String payload) {
    try {
      Mac sha256HMAC = Mac.getInstance(ALGORITHM);
      SecretKeySpec keySpec = new SecretKeySpec(secret, ALGORITHM);
      sha256HMAC.init(keySpec);
      byte[] mac_data = sha256HMAC.doFinal(payload.getBytes(CHARSET));
      return toHexString(mac_data);
    } catch (Exception ex) {
      throw new RuntimeException(ex);
    }
  }

  private String toHexString(byte[] bytes) {
    Formatter formatter = new Formatter();
    for (byte b : bytes) {
      formatter.format("%02x", b);
    }
    return formatter.toString().toLowerCase();
  }
}
