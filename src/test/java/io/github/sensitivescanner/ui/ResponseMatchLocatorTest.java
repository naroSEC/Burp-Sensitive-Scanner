package io.github.sensitivescanner.ui;

import org.junit.jupiter.api.Test;
import java.nio.charset.StandardCharsets;
import static org.junit.jupiter.api.Assertions.*;

class ResponseMatchLocatorTest {
    @Test void locatesRawMatchAtItsByteOffset(){
        byte[] response="HTTP/1.1 200 OK\r\n\r\nprefix TOKEN-4815 suffix".getBytes(StandardCharsets.UTF_8);
        var target=ResponseMatchLocator.locate(response,"TOKEN-4815","");
        assertNotNull(target);assertEquals("TOKEN-4815",target.expression());assertEquals(index(response,"TOKEN-4815"),target.offset());
    }

    @Test void locatesUrlEncodedMatchWhenDecodedValueIsNotPresent(){
        byte[] response="HTTP/1.1 200 OK\r\n\r\nsecret%3Dalpha%20beta".getBytes(StandardCharsets.UTF_8);
        var target=ResponseMatchLocator.locate(response,"secret=alpha beta","");
        assertNotNull(target);assertEquals("secret%3Dalpha%20beta",target.expression());
    }

    @Test void fallsBackToResponseFieldAndBoundsLargeSearchExpressions(){
        byte[] response="HTTP/1.1 200 OK\r\nX-Secret: encoded-value\r\n\r\n".getBytes(StandardCharsets.UTF_8);
        var field=ResponseMatchLocator.locate(response,"missing-value","X-Secret");assertNotNull(field);assertEquals("X-Secret",field.expression());
        String large="A".repeat(800);byte[] largeResponse=("HTTP/1.1 200 OK\r\n\r\n"+large).getBytes(StandardCharsets.UTF_8);var bounded=ResponseMatchLocator.locate(largeResponse,large,"");assertNotNull(bounded);assertEquals(512,bounded.expression().length());
    }

    private int index(byte[] source,String value){return new String(source,StandardCharsets.UTF_8).indexOf(value);}
}
