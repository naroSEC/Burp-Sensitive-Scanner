package io.github.sensitivescanner.model;

public enum ScanArea {
    REQUEST_URL("REQ URL"),
    REQUEST_HEADERS("REQ Headers"),
    REQUEST_BODY("REQ Body"),
    RESPONSE_HEADERS("RES Headers"),
    RESPONSE_BODY("RES Body");

    private final String label;
    ScanArea(String label) { this.label = label; }
    public String label() { return label; }

    public static ScanArea from(Location location) {
        return switch (location) {
            case REQUEST_URL, REQUEST_QUERY -> REQUEST_URL;
            case REQUEST_HEADER, REQUEST_COOKIE -> REQUEST_HEADERS;
            case REQUEST_BODY -> REQUEST_BODY;
            case RESPONSE_HEADER, RESPONSE_COOKIE -> RESPONSE_HEADERS;
            case RESPONSE_BODY, RESPONSE_JAVASCRIPT -> RESPONSE_BODY;
        };
    }
}
