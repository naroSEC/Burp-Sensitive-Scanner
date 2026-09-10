package io.github.sensitivescanner.scanner;
import io.github.sensitivescanner.model.Location;
public record TextArtifact(String text, Location location, String fieldName, String path, int depth) {}
