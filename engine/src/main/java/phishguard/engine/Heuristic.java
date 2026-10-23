package phishguard.engine;

import java.util.List;

@FunctionalInterface
public interface Heuristic {
    List<Finding> analyze(Email email);
}
