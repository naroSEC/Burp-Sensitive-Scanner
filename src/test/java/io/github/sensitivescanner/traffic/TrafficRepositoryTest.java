package io.github.sensitivescanner.traffic;

import io.github.sensitivescanner.TestFixtures;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class TrafficRepositoryTest {
    @Test void deduplicatesIdenticalTransactionsButKeepsDifferentBodies(){TrafficRepository r=new TrafficRepository(100);var a=TestFixtures.response("one");var b=TestFixtures.response("two");assertTrue(r.add(a));assertFalse(r.add(a));assertTrue(r.add(b));assertEquals(2,r.size());}
    @Test void evictsOldestAtBound(){TrafficRepository r=new TrafficRepository(100);for(int i=0;i<101;i++)r.add(TestFixtures.response("body-"+i));assertEquals(100,r.size());assertEquals(1,r.evicted());}
}
