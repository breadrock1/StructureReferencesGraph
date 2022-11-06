public class StructureReference {

    private final Structure toStructureRef;

    private final Structure fromStructureRef;

    public StructureReference(Structure fromAddr, Structure toAddr) {
        this.fromStructureRef = fromAddr;
        this.toStructureRef = toAddr;
    }

    public Structure getToStructure() {
        return this.toStructureRef;
    }

    public Structure getFromStructure() {
        return this.fromStructureRef;
    }

}
