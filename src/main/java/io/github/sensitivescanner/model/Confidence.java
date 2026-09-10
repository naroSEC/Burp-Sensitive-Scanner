package io.github.sensitivescanner.model;
public enum Confidence { HIGH, MEDIUM, LOW;
    public boolean meets(Confidence minimum) { return ordinal() <= minimum.ordinal(); }
}
