import io.restassured.RestAssured;
import io.restassured.filter.log.RequestLoggingFilter;
import io.restassured.filter.log.ResponseLoggingFilter;
import io.restassured.internal.http.Status;
import io.restassured.response.Response;
import io.restassured.response.ResponseBody;
import io.restassured.specification.RequestSpecification;
import org.json.JSONObject;
import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import static io.restassured.RestAssured.given;

public class ApiTest {
    //Setup
    @BeforeClass
    public void setup() {
        RestAssured.baseURI = "http://127.0.0.1:8088";

        //Log all request and response
        RestAssured.filters(new RequestLoggingFilter(), new ResponseLoggingFilter());
    }

    public void shutdown() {
        String body = "shutdown";
         given()
                .header("Content-type", "application/json")
                .and()
                .body(body)
                .when()
                .post("/hash");
    }

    //Method to encrypt password using SHA-512 (Source: Google!)
    public static String encryptThisString(String input) {
        try {
            // getInstance() method is called with algorithm SHA-512
            MessageDigest md = MessageDigest.getInstance("SHA-512");

            // digest() method is called
            // to calculate message digest of the input string
            // returned as array of byte
            byte[] messageDigest = md.digest(input.getBytes());

            // Convert byte array into signum representation
            BigInteger no = new BigInteger(1, messageDigest);

            // Convert message digest into hex value
            String hashtext = no.toString(16);

            // Add preceding 0s to make it 32 bit
            while (hashtext.length() < 32) {
                hashtext = "0" + hashtext;
            }

            // return the HashText
            return hashtext;
        }

        // For specifying wrong message digest algorithms
        catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    //Tests for POST /hash endpoint
    @Test
    public void testPostHash() throws IOException {
        RequestSpecification request = given();

        try {
            //test correct password key
            JSONObject requestParams1 = new JSONObject();
            requestParams1.put("password", "angrymonkey");
            request.body(requestParams1.toString());
            Response response1 = request.post("/hash");

            //test incorrect password key
            JSONObject requestParams2 = new JSONObject();
            requestParams2.put("notPassword", "notangrymonkey");
            request.body(requestParams2.toString());
            Response response2 = request.post("/hash");

            //test empty password value
            JSONObject requestParams3 = new JSONObject();
            requestParams3.put("password", "");
            request.body(requestParams3.toString());
            Response response3 = request.post("/hash");

            //test empty json
            JSONObject requestParams4 = new JSONObject();
            requestParams4.clear();
            request.body(requestParams4.toString());
            Response response4 = request.post("/hash");

            //test result for correct password key
            Assert.assertTrue(Status.SUCCESS.matches(response1.statusCode()));
            //test result for incorrect password key
            Assert.assertTrue(Status.FAILURE.matches(response2.statusCode()));
            //test result for empty password value
            Assert.assertTrue(Status.FAILURE.matches(response3.statusCode()));
            //test result for empty json
            Assert.assertTrue(Status.FAILURE.matches(response4.statusCode()));
        } catch (Exception e) {
            System.out.println(e);
        } finally {
            shutdown();
        }
    }

    //Tests for GET /hash endpoint
    @Test
    public void testGetHash() {
        RequestSpecification request = given();
        try {
            String passwordValue = "angrymonkey";
            String encryptedPassword = encryptThisString(passwordValue);
            String encodedPassword = Base64.getEncoder().encodeToString(encryptedPassword.getBytes());

            //send a POST /hash request for setup
            JSONObject requestParams = new JSONObject();
            requestParams.put("password", passwordValue);
            request.body(requestParams.toString());
            request.post("/hash");

            Response response1 = request.get("/hash/1");
            //Store the response body to compare hash values
            ResponseBody body = response1.getBody();
            String bodyAsString = body.asString();

            Response response2 = request.get("/hash/2");
            Response response3 = request.get("/hash/");

            //Test result for valid job identifier
            Assert.assertTrue(Status.SUCCESS.matches(response1.statusCode()));
            //Test result for a nonexistent job identifier
            Assert.assertTrue(Status.FAILURE.matches(response2.statusCode()));
            //Test result for an invalid job identifier
            Assert.assertTrue(Status.FAILURE.matches(response3.statusCode()));
            //Check the encoded password
            Assert.assertEquals(bodyAsString, encodedPassword);
        } catch (Exception e) {
            System.out.println(e);
        } finally {
            shutdown();
        }
    }

    //Tests for GET /stats endpoint
    @Test
    public void testGetStats() {
        RequestSpecification request = given();
        try {
            //send two POST /hash requests for setup
            JSONObject requestParams1 = new JSONObject();
            requestParams1.put("password", "angrymonkey");
            request.body(requestParams1.toString());
            Response response1 = request.post("/hash");
            Long time1 = response1.getTime();

            JSONObject requestParams2 = new JSONObject();
            requestParams2.put("password", "notangrymonkey");
            request.body(requestParams2.toString());
            Response response2 = request.post("/hash");
            Long time2 = response2.getTime();

            String expectedAverageTime = Long.toString((time1 + time2) / 2);

            //Store the response body to check the key values returned from the api
            Response response3 = request.get("/stats");
            String totalRequest = response3.jsonPath().getString("TotalRequests");
            String averageTime = response3.jsonPath().getString("AverageTime");

            //Test result for a valid request
            Assert.assertTrue(Status.SUCCESS.matches(response3.statusCode()));
            //Test result for the expected number of total requests
            Assert.assertEquals(totalRequest, "2");
            //Test result for the expected average time
            Assert.assertEquals(averageTime, expectedAverageTime);
        } catch (Exception e) {
            System.out.println(e);
        } finally {
            shutdown();
        }
    }
}
