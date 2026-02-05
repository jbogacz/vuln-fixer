# Gradle Dependency Resolution vs GitLab Vulnerability Scanning

## How Gradle Dependency Resolution Works

When multiple dependencies request different versions of the same library, Gradle uses **conflict resolution** to pick a single version (by default, the highest).

### Gradle Conflict Resolution Strategies

#### 1. Default: Highest Version Wins

Gradle's default strategy selects the **highest version** among all requested versions:

```
Requested versions: 1.0.0, 1.2.0, 1.5.0
Resolved version:   1.5.0 (highest wins)
```

#### 2. Resolution via BOM (Bill of Materials)

When using a BOM (like Spring Boot), the BOM's version takes precedence:

```kotlin
dependencies {
    implementation(platform("org.springframework.boot:spring-boot-dependencies:3.5.8"))
    implementation("com.fasterxml.jackson.core:jackson-databind")  // version from BOM
}
```

#### 3. Explicit Version Override

Direct declarations override transitive versions:

```kotlin
dependencies {
    implementation("com.example:library:2.0.0")  // explicit - wins over transitive
}
```

#### 4. Dependency Constraints

Constraints enforce minimum versions without adding the dependency:

```kotlin
dependencies {
    constraints {
        implementation("com.example:library:1.5.0") {
            because("Security fix required")
        }
    }
}
```

#### 5. Force Resolution (Not Recommended)

Forces a specific version regardless of conflicts:

```kotlin
configurations.all {
    resolutionStrategy {
        force("com.example:library:1.5.0")
    }
}
```

#### 6. Strict Versions

Fails the build if a different version is requested:

```kotlin
dependencies {
    implementation("com.example:library") {
        version {
            strictly("1.5.0")
        }
    }
}
```

### Resolution Order (Precedence)

1. `strictly` versions (fail if conflict)
2. `force` resolutions
3. Explicit dependency declarations
4. Constraints
5. BOM versions
6. Highest transitive version (default)

```
Declared in dependency tree:
├── Spring Boot BOM → jackson-databind:2.19.4
└── logstash-logback-encoder:7.2 → jackson-databind:2.13.3

Gradle conflict resolution picks HIGHEST version:
└── Runtime classpath → jackson-databind:2.19.4 (only this JAR is used)
```

## What Actually Happens at Runtime

| Stage | Version | In classpath? |
|-------|---------|---------------|
| logstash-logback-encoder **requests** | 2.13.3 | No |
| Spring Boot **requests** | 2.19.4 | No |
| Gradle **resolves to** | 2.19.4 | **Yes** (only this) |

The vulnerable `2.13.3` JAR is **never downloaded or used at runtime**. Only `2.19.4` is included in the final classpath.

## Why GitLab Flags It Anyway

GitLab's dependency scanner analyzes the **declared dependency tree** (what libraries request), not the **resolved classpath** (what actually runs).

It sees:
```
logstash-logback-encoder:7.2
└── jackson-databind:2.13.3  ← GitLab flags this declaration
```

### Reasons for this behavior:

1. **Scanner limitation** - Some scanners don't understand Gradle's conflict resolution mechanism
2. **Supply chain concern** - A transitive dependency declares a vulnerable version, which is flagged regardless of resolution
3. **Conservative approach** - Scanners err on the side of caution

## Summary

| Question | Answer |
|----------|--------|
| Was vulnerable version in runtime classpath? | **No** |
| Was vulnerable version declared in dependency tree? | **Yes** |
| Was GitLab correct about runtime risk? | **No** (false positive) |
| Was GitLab correct about declaration existing? | **Yes** |

## How to Fix

### Option A: Gradle Constraints (Override)

Forces minimum version but doesn't remove the vulnerable declaration from the tree:

```kotlin
dependencies {
    constraints {
        implementation("com.example:library:1.2.3") {
            because("CVE-XXXX-YYYY: Description of vulnerability")
        }
    }
}
```

**Result:** Runtime safe, but GitLab may still flag the transitive declaration.

### Option B: Upgrade Transitive Dependency Source (Recommended)

Upgrade the library that pulls the vulnerable transitive dependency:

```kotlin
// Instead of fixing the symptom (jackson-databind version),
// fix the source (logstash-logback-encoder version)
api("net.logstash.logback:logstash-logback-encoder:8.1")  // uses jackson 2.18.3
```

**Result:** Vulnerable version removed from dependency tree entirely. GitLab satisfied.

### Option C: Exclude and Re-declare

Exclude the transitive dependency and declare the safe version explicitly:

```kotlin
implementation("com.example:library:1.0.0") {
    exclude(group = "com.vulnerable", module = "library")
}
implementation("com.vulnerable:library:2.0.0")  // safe version
```

**Result:** Works but adds maintenance burden.

## Verification Commands

### Check resolved version
```bash
./gradlew :module:dependencyInsight --dependency com.example:library
```

### Check if vulnerable version still declared
```bash
./gradlew :module:dependencyInsight --dependency com.example:library 2>/dev/null | grep "vulnerable-version"
```

### Check all modules
```bash
./gradlew dependencies --configuration compileClasspath | grep "library"
```

## Key Takeaways

1. **Gradle conflict resolution protects runtime** - Only the highest version is used
2. **GitLab scans declarations, not resolutions** - It flags what's requested, not what's used
3. **Fix the source, not the symptom** - Upgrading the library that pulls the vulnerable dependency is cleaner than adding constraints
4. **Constraints are defensive documentation** - They ensure minimum versions but don't remove vulnerable declarations from the tree