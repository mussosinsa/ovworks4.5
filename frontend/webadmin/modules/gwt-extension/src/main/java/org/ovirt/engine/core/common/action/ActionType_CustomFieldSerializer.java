package org.ovirt.engine.core.common.action;

import com.google.gwt.user.client.rpc.SerializationException;
import com.google.gwt.user.client.rpc.SerializationStreamReader;
import com.google.gwt.user.client.rpc.SerializationStreamWriter;

/**
 * Serializes action types by their stable engine value.
 *
 * <p>The default GWT enum serializer includes the Java enum's type signature in
 * the RPC payload. Consequently, adding an action can invalidate requests when
 * WebAdmin and the engine are updated at slightly different times. The numeric
 * action value is the wire identifier already maintained by {@link ActionType},
 * so using it here keeps the RPC representation independent of enum changes.</p>
 */
public class ActionType_CustomFieldSerializer {

    public static void deserialize(SerializationStreamReader streamReader,
            ActionType instance) {
        // Enum instances are fully initialized by instantiate().
    }

    public static ActionType instantiate(SerializationStreamReader streamReader)
            throws SerializationException {
        int value = streamReader.readInt();
        ActionType actionType = ActionType.forValue(value);
        if (actionType == null) {
            throw new SerializationException("Unknown action type value: " + value); //$NON-NLS-1$
        }
        return actionType;
    }

    public static void serialize(SerializationStreamWriter streamWriter,
            ActionType instance) throws SerializationException {
        streamWriter.writeInt(instance.getValue());
    }
}
