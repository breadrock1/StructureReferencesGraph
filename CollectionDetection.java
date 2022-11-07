import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.Spliterator;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

import ghidra.app.script.GhidraScript;
import ghidra.app.services.GraphDisplayBroker;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
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
    private ReferenceManager referenceManager;

    private AttributedGraph graph;

    private final static Integer POINTER_ADDRESS_OFFSET = 16;


    @Override
    @SuppressWarnings("deprecation")
    public void run() throws Exception {
        this.program = currentProgram;
        this.pluginTool = getState().getTool();
        this.referenceManager = this.program.getReferenceManager();

        List<Address> memoryAddresses = loadNonNullMemoryAddresses();
        Map<Address, List<Reference>> addressReferences = loadAddressReferences(memoryAddresses);
        List<Set<Address>> neigbouringAddresses = loadNeighbouringAddresses(addressReferences);
        List<MemoryStructure> memoryStructures = buildMemoryStructures(neigbouringAddresses);

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

    private Map<Address, List<Reference>> loadAddressReferences(List<Address> addresses) {
        return addresses.stream()
                .collect(Collectors.toMap(addr -> addr, addr -> this.getPointerReferences(addr)))
                .entrySet()
                .stream()
                .filter(entry -> !entry.getValue().isEmpty())
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
    }

    private List<Set<Address>> loadNeighbouringAddresses(Map<Address, List<Reference>> addresses) {
        List<Address> memoryAddresses = addresses.keySet()
                .stream()
                .sorted()
                .collect(Collectors.toList());

        Set<Address> neighboursAddresses = new HashSet<>();
        List<Set<Address>> allNeighbours = new ArrayList<>();

        Address prevAddress = memoryAddresses.get(0);
        for (int i = 1; i < memoryAddresses.size(); ++i) {
            Address currAddress = memoryAddresses.get(i);
            Long prevAddressOffset = prevAddress.getOffset();
            Long currAddressOffset = currAddress.getOffset();

            if ((currAddressOffset - prevAddressOffset) <= POINTER_ADDRESS_OFFSET) {
                neighboursAddresses.add(currAddress);
                neighboursAddresses.add(prevAddress);

            } else {
                neighboursAddresses.add(prevAddress);
                allNeighbours.add(neighboursAddresses);
                neighboursAddresses = new HashSet<>();
            }

            prevAddress = currAddress;
        }

        return allNeighbours;
    }

    private List<MemoryStructure> buildMemoryStructures(List<Set<Address>> allNeighbours) {
        List<MemoryStructure> memoryStructures = allNeighbours.stream()
                .map(Set::stream)
                .map(Stream::toList)
                .filter(list -> !list.isEmpty())
                .map(suit -> new MemoryStructure(suit.get(0), suit))
                .collect(Collectors.toList());

        return memoryStructures;
    }

    private void generateMemoryStructureGraph(List<MemoryStructure> memoryStructures, Map<Address, List<Reference>> references) {
        Map<MemoryStructure, AttributedVertex> graphAttributes = memoryStructures.stream()
                .collect(Collectors.toMap(strct -> strct, strct -> vertex(strct.getAddress(), strct.getLastAddress())));

        Set<Reference> referenceValues = references.values()
                .stream()
                .flatMap(List::stream)
                .collect(Collectors.toSet());

        for (Reference currReference : referenceValues) {
            Address toAddress = currReference.getToAddress();
            Address fromAddress = currReference.getFromAddress();

            Optional<MemoryStructure> optToMemStructure = graphAttributes.keySet()
                    .stream()
                    .filter(strct -> strct.isAddressContains(toAddress))
                    .findFirst();

            Optional<MemoryStructure> optFromMemStructure = graphAttributes.keySet()
                    .stream()
                    .filter(strct -> strct.isAddressContains(fromAddress))
                    .findFirst();

            AttributedVertex toMemVertex;
            MemoryStructure toMemStructure;
            if (!optToMemStructure.isPresent()) {
                toMemStructure = new MemoryStructure(toAddress, List.of(toAddress));
                toMemVertex = vertex(toMemStructure.getAddress(), toMemStructure.getLastAddress());
                graphAttributes.put(toMemStructure, toMemVertex);
            } else {
                toMemStructure = optToMemStructure.get();
                toMemVertex = graphAttributes.get(toMemStructure);
            }

            AttributedVertex fromMemVertex;
            MemoryStructure fromMemStructure;
            if (!optFromMemStructure.isPresent()) {
                fromMemStructure = new MemoryStructure(fromAddress, List.of(fromAddress));
                fromMemVertex = vertex(fromMemStructure.getAddress(), fromMemStructure.getLastAddress());
                graphAttributes.put(fromMemStructure, fromMemVertex);
            } else {
                fromMemStructure = optFromMemStructure.get();
                fromMemVertex = graphAttributes.get(fromMemStructure);
            }

            edge(fromMemVertex, toMemVertex);
        }
    }

    private AttributedVertex vertex(Address first, Address second) {
        String vertexLabel = String.format(
                "0x%s -> 0x%s",
                Long.toHexString(first.getOffset()),
                Long.toHexString(second.getOffset())
        );

        return graph.addVertex(vertexLabel, vertexLabel);
    }

    private AttributedEdge edge(AttributedVertex v1, AttributedVertex v2) {
        return graph.addEdge(v1, v2);
    }

}


class MemoryStructure {

    private final Address startAddress;

    private final List<Address> pointers;

    public MemoryStructure(Address address, List<Address> pointers) {
        this.startAddress = address;
        this.pointers = pointers;
    }

    public Address getAddress() {
        return this.startAddress;
    }

    public Address getLastAddress() {
        int poitersCount = this.pointers.size();
        return this.pointers.get(poitersCount - 1);
    }

    public List<Address> getPointers() {
        return this.pointers;
    }

    public boolean isAddressContains(Address address) {
        return this.pointers.contains(address);
    }

}

