package life.qbic.data.views.map;

import com.vaadin.flow.component.orderedlayout.VerticalLayout;
import life.qbic.data.components.leafletmap.LeafletMap;
import com.vaadin.flow.router.Route;
import com.vaadin.flow.router.PageTitle;
import life.qbic.data.views.MainLayout;
import javax.annotation.security.RolesAllowed;

@PageTitle("Map")
@Route(value = "", layout = MainLayout.class)
@RolesAllowed("user")
public class MapView extends VerticalLayout {

    private LeafletMap map = new LeafletMap();

    public MapView() {
        setSizeFull();
        setPadding(false);
        map.setSizeFull();
        map.setView(55.0, 10.0, 4);
        add(map);
    }
}
