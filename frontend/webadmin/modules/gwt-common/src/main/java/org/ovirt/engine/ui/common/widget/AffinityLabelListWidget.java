package org.ovirt.engine.ui.common.widget;

import org.ovirt.engine.core.common.businessentities.Label;
import org.ovirt.engine.ui.uicommonweb.models.ListModel;
import org.ovirt.engine.ui.uicompat.ConstantsManager;
import org.ovirt.engine.ui.uicompat.UIConstants;

public class AffinityLabelListWidget extends AbstractItemListWidget<Label> {
    private static final UIConstants constants = ConstantsManager.getInstance().getConstants();

    @Override
    public void init(ListModel<Label> labelModel) {
        super.init(labelModel);
        itemListLabel.setText(constants.selectedAffinityLabels());
    }

    @Override
    protected String noItemsText() {
        return constants.noAffinityLabelsSelected();
    }
}
