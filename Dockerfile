# ── Stage 1: build ───────────────────────────────────────────────────────────
FROM eclipse-temurin:21-jdk-alpine AS build

WORKDIR /workspace

# Copy dependency descriptors first so Docker cache is reused when only source changes
COPY pom.xml .
COPY .mvn/ .mvn/
COPY mvnw .

RUN chmod +x mvnw && ./mvnw dependency:go-offline -q

# Copy source (test sources are excluded via .dockerignore)
COPY src/ src/

# Package without running tests — they belong in CI, not in the image build
RUN ./mvnw package -DskipTests -q

# ── Stage 2: runtime ──────────────────────────────────────────────────────────
# Distroless: no shell, no package manager, minimal attack surface.
# The "nonroot" variant runs as uid 65532 (nonroot) by default.
FROM gcr.io/distroless/java21-debian12:nonroot

WORKDIR /app

# Copy only the fat JAR produced by spring-boot-maven-plugin
COPY --from=build /workspace/target/certvalidator-*.jar app.jar

# Distroless nonroot image already sets USER nonroot (uid 65532).
# Declare it explicitly so tooling (scanners, Kubernetes securityContext checks) can verify it.
USER nonroot

EXPOSE 8443

ENTRYPOINT ["java", "-jar", "app.jar"]
