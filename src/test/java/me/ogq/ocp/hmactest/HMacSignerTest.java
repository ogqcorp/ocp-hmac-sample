package me.ogq.ocp.hmactest;

import static org.junit.Assert.assertTrue;

import java.net.URI;
import org.junit.Before;
import org.junit.Test;


public class HMacSignerTest {
  private HMacSigner hMacSigner;
  @Before
  public void setup() {
    hMacSigner = new HMacSigner("api-key", "secret");

  }

  @Test
  public void sign() {
    URI uri = URI.create("https://stg.api.ogq.me/cps/products?creatorId=567890");
    URI signed = hMacSigner.sign(uri);

    assertTrue(hMacSigner.validate(signed));
  }
}