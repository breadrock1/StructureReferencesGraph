import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.Spliterator;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

import ghidra.app.script.GhidraScript;
import ghidra.app.services.GraphDisplayBroker;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.service.graph.AttributedEdge;
import ghidra.service.graph.AttributedGraph;
import ghidra.service.graph.AttributedVertex;
import ghidra.service.graph.EmptyGraphType;
import ghidra.service.graph.GraphDisplay;


public class CollectionDetection extends GhidraScript {

    private Program program;
    private PluginTool pluginTool;
    private AddressFactory addressFactory;
    private ReferenceManager referenceManager;

    private AttributedGraph graph;


    @Override
    @SuppressWarnings("deprecation")
    public void run() throws Exception {
        this.program = currentProgram;
        this.pluginTool = getState().getTool();
        this.addressFactory = this.program.getAddressFactory();
        this.referenceManager = this.program.getReferenceManager();

        List<Address> memoryAddresses = loadNonNullMemoryAddresses();
        Map<Address, List<Reference>> addressReferences = loadAddressReferences(memoryAddresses);
        Map<Address, Long> addressesTableSize = generateAddressesTableSize(addressReferences);
        Map<Address, MemoryStructure> memoryStructures = generateAddressesTableMap(addressesTableSize);

        GraphDisplayBroker service = this.pluginTool.getService(GraphDisplayBroker.class);
        GraphDisplay display = service.getDefaultGraphDisplay(false, this.monitor);
        this.graph = new AttributedGraph("Pointer References Graph", new EmptyGraphType());
        generateMemoryStructureGraph(memoryStructures, addressReferences);
        display.setGraph(this.graph, "Pointer References Graph", false, this.monitor);
    }

    private List<Address> loadNonNullMemoryAddresses() {
        AddressIterator addressIterator = currentProgram.getMemory().getAddresses(true);
        return StreamSupport.stream(addressIterator.spliterator(), false)
                .sorted()
                .collect(Collectors.toList());
    }

    private Map<Address, List<Reference>> loadAddressReferences(List<Address> addresses) {
        Map<Address, List<Reference>> addressReferencess = addresses.stream()
                .collect(Collectors.toMap(addr -> addr, addr -> this.getPointerReferences(addr)))
                .entrySet()
                .stream()
                .filter(entry -> !entry.getValue().isEmpty())
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));

        return addressReferencess;
    }

    private List<Reference> getPointerReferences(Address address) {
        List<Reference> availableReferences = new ArrayList<>();

        if (this.referenceManager.getReferenceCountTo(address) > 0) {
            ReferenceIterator refsIter = referenceManager.getReferencesTo(address);
            Spliterator<Reference> refsSpliter = refsIter.spliterator();
            List<Reference> references = StreamSupport.stream(refsSpliter, false)
                    .collect(Collectors.toList());

            availableReferences.addAll(references);
        }

        if (this.referenceManager.getReferenceCountFrom(address) > 0) {
            Reference[] refsArray = referenceManager.getReferencesFrom(address);
            List<Reference> references = List.of(refsArray);

            availableReferences.addAll(references);
        }

        return availableReferences;
    }

    private Map<Address, Long> generateAddressesTableSize(Map<Address, List<Reference>> addresses) {
        List<Address> toAddrsList = addresses.values()
                .stream()
                .flatMap(List::stream)
                .map(Reference::getToAddress)
                .sorted()
                .collect(Collectors.toList());

        Address prevAddr = toAddrsList.get(0);
        Map<Address, Long> tablesFrameSize = new HashMap<>();
        for (int i = 1; i < toAddrsList.size(); ++i) {
            Address currAddr = toAddrsList.get(i);
            Long addrsOffset = currAddr.getOffset() - prevAddr.getOffset() - 1;
            tablesFrameSize.put(prevAddr, (addrsOffset <= 128) ? addrsOffset : 128);

            prevAddr = currAddr;
        }

        tablesFrameSize.put(prevAddr, 128L);

        return tablesFrameSize;
    }

    private Map<Address, MemoryStructure> generateAddressesTableMap(Map<Address, Long> tablesFrameSize) {
        Map<Address, MemoryStructure> memStrctMap = new HashMap<>();
        for (Map.Entry<Address, Long> tableSizeEntry : tablesFrameSize.entrySet()) {
            Address startAddr = tableSizeEntry.getKey();
            Long endAddrOffset = startAddr.getOffset() + tableSizeEntry.getValue();

            AddressSpace currSpace = startAddr.getAddressSpace();
            Address endAddr = this.addressFactory.getAddress(currSpace.getSpaceID(), endAddrOffset);
            AddressSet tableSetAddrs = this.addressFactory.getAddressSet(startAddr, endAddr);

            memStrctMap.put(startAddr, new MemoryStructure(startAddr, tableSetAddrs));
        }

        return memStrctMap;
    }


    private void generateMemoryStructureGraph(Map<Address, MemoryStructure> memoryStructures, Map<Address, List<Reference>> references) {
        Set<Reference> referenceValues = references.values()
                .stream()
                .flatMap(List::stream)
                .collect(Collectors.toSet());

        Map<MemoryStructure, AttributedVertex> graphAttributes = memoryStructures.values()
                .stream()
                .collect(Collectors.toMap(strct -> strct, strct -> vertex(strct)));

        for (Reference currReference : referenceValues) {
            Address toAddress = currReference.getToAddress();
            Address fromAddress = currReference.getFromAddress();

            MemoryStructure toMemStrct = memoryStructures.get(toAddress);
            AttributedVertex toMemStrctVertex = graphAttributes.get(toMemStrct);

            Optional<MemoryStructure> optFromMemStrct = memoryStructures.values()
                    .stream()
                    .filter(strct -> strct.contains(fromAddress))
                    .findFirst();

            AttributedVertex fromMemStrctVertex = (optFromMemStrct.isPresent())
                    ? graphAttributes.get(optFromMemStrct.get()) : vertex(fromAddress);

            edge(fromMemStrctVertex, toMemStrctVertex);
        }
    }

    private AttributedVertex vertex(Address address) {
        String vertexLabel = String.format("0x%s", Long.toHexString(address.getOffset()));
        return graph.addVertex(vertexLabel, vertexLabel);
    }

    private AttributedVertex vertex(MemoryStructure memStructure) {
        String vertexLabel = String.format(
                "0x%s -> 0x%s\nAddress count: %s",
                Long.toHexString(memStructure.getStartAddress().getOffset()),
                Long.toHexString(memStructure.getLastAddress().getOffset()),
                memStructure.getAddressSetSize()
        );

        return graph.addVertex(vertexLabel, vertexLabel);

    }

    private AttributedEdge edge(AttributedVertex v1, AttributedVertex v2) {
        return graph.addEdge(v1, v2);
    }

}


class MemoryStructure {

    private final Address startAddress;

    private final AddressSet addressSet;

    private final long addressSetSize;

    public MemoryStructure(Address address, AddressSet addressSet) {
        this.startAddress = address;
        this.addressSet = addressSet;
        this.addressSetSize = addressSet.getNumAddresses();
    }

    public Address getStartAddress() {
        return this.startAddress;
    }

    public AddressSet getAddressSet() {
        return this.addressSet;
    }

    public long getAddressSetSize() {
        return this.addressSetSize;
    }

    public Address getLastAddress() {
        return this.addressSet.getMaxAddress();
    }

    public boolean contains(Address address) {
        return this.addressSet.contains(address);
    }

}
