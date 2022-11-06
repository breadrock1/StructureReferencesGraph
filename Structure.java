import com.sun.tools.javac.util.List;

import java.util.ArrayList;

public class Structure {

    private final Address startAddress;

    private final List<Address> strctPointers;

    private final List<StructureReference> references;

    public Structure(Address startAddress, List<Address> pointers) {
        this.startAddress = startAddress;
        this.strctPointers = pointers;
        this.references = new ArrayList<StructureReference>();
    }

    public appendReference(StructureReference reference) {
        this.references.append(reference);
    }

    public Address getStructureAddress() {
        return this.startAddress;
    }

}
